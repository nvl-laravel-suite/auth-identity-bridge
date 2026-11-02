<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Auth;

use IdentityPlatform\Laravel\Authorization\AuthorizationClient;
use IdentityPlatform\Laravel\Authorization\Principal;
use IdentityPlatform\Laravel\Events\AuthenticatedSessionEstablished;
use IdentityPlatform\Laravel\Events\ContextSelected;
use IdentityPlatform\Laravel\Events\LifecycleNotifications;
use IdentityPlatform\Laravel\Events\LocalSessionEnded;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Oidc\OidcClient;
use IdentityPlatform\Laravel\Repositories\LoginRepository;
use IdentityPlatform\Laravel\Repositories\SessionRepository;
use IdentityPlatform\Laravel\Support\IdentityConfig;
use IdentityPlatform\Laravel\Support\IdentityHttp;
use IdentityPlatform\Laravel\Support\IdentityVault;
use IdentityPlatform\Laravel\Support\SafeReturn;
use IdentityPlatform\Laravel\Sync\UserSynchronizer;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Throwable;

class SessionManager
{
    public function __construct(private IdentityConfig $config, private IdentityVault $vault, private LoginRepository $logins, private SessionRepository $sessions, private OidcClient $oidc, private AuthorizationClient $authorization, private UserSynchronizer $users, private IdentityHttp $http, private LifecycleNotifications $notifications) {}

    public function start(Request $request, mixed $returnPath = '/', bool $resource = false): string
    {
        $intent = ['nonce' => bin2hex(random_bytes(32)), 'verifier' => rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '='), 'resource' => $resource, 'return_path' => SafeReturn::path($returnPath), 'created_at' => now()->timestamp];
        $state = $this->logins->create($request->session()->getId(), $intent, 'login');

        return $this->oidc->authorization($intent + ['state' => $state]);
    }

    public function complete(Request $request, array $callback): string
    {
        $callback = CallbackInput::validate($request, $callback);
        $intent = $this->logins->consume((string) ($callback['state'] ?? ''), $request->session()->getId(), 'login');
        $tokens = $this->oidc->exchange($callback, $intent);
        $contexts = $this->authorization->contexts($tokens['access_token'], $tokens['subject'], $tokens['sid']);
        $this->requireLiveIntent($intent);
        if ($contexts['contexts'] === []) {
            throw new IdentityException('access_denied', 403);
        }
        $user = $this->users->sync($tokens['userinfo']);
        $this->requireLiveIntent($intent);
        if ($old = $this->sessions->find($this->id($request))) {
            $this->end($old);
        }
        $id = bin2hex(random_bytes(32));
        $created = $this->sessions->create(['id' => $id, 'user_id' => $user->id, 'subject' => $tokens['subject'], 'sid' => $tokens['sid'], 'token_vault' => $this->vault->seal($tokens, 'session:'.$id), 'selection' => [], 'snapshot' => null, 'context_version' => 1, 'token_generation' => 1, 'started_at' => now(), 'last_activity_at' => now(), 'expires_at' => now()->addSeconds((int) $this->config->value('local.absolute_seconds', 43200))]);
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $request->session()->put('identity.session', $id);
        $request->session()->put('identity.return_path', SafeReturn::path($intent['return_path'] ?? '/'));

        $this->notifications->afterCommit($created->getConnection(), new AuthenticatedSessionEstablished($this->config->context()->name(), $created->subject, $created->context_version));

        return parse_url($this->config->url('contexts'), PHP_URL_PATH);
    }

    public function current(Request $request): ?IdentitySession
    {
        $row = $this->resolveCurrent($request);
        if (! $row && $request->hasSession()) {
            $request->session()->forget('identity.session');
        }

        return $row;
    }

    private function resolveCurrent(Request $request): ?IdentitySession
    {
        $row = $this->sessions->find($this->id($request));
        if (! $row) {
            return null;
        }
        if (! $this->live($row)) {
            $this->end($row);

            return null;
        }
        $tokens = $this->vault->open($row->token_vault, 'session:'.$row->id);
        if (($tokens['expires_at'] ?? 0) <= now()->timestamp + 15) {
            if ($row->getConnection()->transactionLevel() > 0) {
                throw new IdentityException('refresh_required', 409);
            }

            return $this->locked($row->id, function ($lock) use ($row): ?IdentitySession {
                $current = $this->sessions->find($row->id);
                if (! $current || ! $this->live($current)) {
                    if ($current) {
                        $this->end($current);
                    }

                    return null;
                }
                $bundle = $this->vault->open($current->token_vault, 'session:'.$current->id);
                if (($bundle['expires_at'] ?? 0) > now()->timestamp + 15) {
                    if (! $this->sessions->publish($current, ['last_activity_at' => now()])) {
                        throw new IdentityException('session_changed', 409);
                    }

                    return $this->sessions->find($current->id);
                }
                $this->renew($lock);
                try {
                    $next = $this->oidc->refresh($bundle);
                } catch (IdentityException $e) {
                    if ($e->status === 401) {
                        $this->end($current);

                        return null;
                    }
                    throw $e;
                }
                $this->renew($lock);
                if (! $this->live($current)) {
                    $this->end($current);

                    return null;
                }
                $user = $this->users->sync($next['userinfo']);
                $this->renew($lock);
                if (! $this->live($current)) {
                    $this->end($current);

                    return null;
                }
                $sourceChange = $user->id !== $current->user_id ? ['application_context' => null, 'context_version' => $current->context_version + 1] : [];
                if (! $this->sessions->publish($current, ['token_vault' => $this->vault->seal($next, 'session:'.$current->id), 'user_id' => $user->id, 'snapshot' => null, 'token_generation' => $current->token_generation + 1, 'last_activity_at' => now()] + $sourceChange)) {
                    throw new IdentityException('session_changed', 409);
                }

                return $this->sessions->find($current->id);
            });
        }
        if (! $this->sessions->publish($row, ['last_activity_at' => now()])) {
            throw new IdentityException('session_changed', 409);
        }

        return $row;
    }

    public function contexts(Request $request): array
    {
        $row = $this->requireSession($request);
        $tokens = $this->tokens($row);
        $result = $this->authorization->contexts($tokens['access_token'], $row->subject, $row->sid);
        $this->assertUnchanged($row);

        return $result + ['local_context_version' => $row->context_version];
    }

    public function select(Request $request, array $selection, int $version): void
    {
        $row = $this->requireSession($request);
        if ($row->context_version !== $version || array_diff(array_keys($selection), ['organizationId', 'roleId'])) {
            throw new IdentityException('context_changed', 409);
        }
        $tokens = $this->tokens($row);
        $contexts = $this->authorization->contexts($tokens['access_token'], $row->subject, $row->sid);
        $found = false;
        foreach ($contexts['contexts'] as $choice) {
            if (($choice['selection'] ?? null) == $selection) {
                $found = true;
                break;
            }
        }
        if (! $found) {
            throw new IdentityException('context_unavailable', 403);
        }
        $snapshot = $this->authorization->snapshot($tokens['access_token'], $row->subject, $row->sid, $selection);
        $this->assertUnchanged($row);
        if (! $this->sessions->publish($row, ['application_context' => null, 'selection' => ['selected' => true] + $selection, 'snapshot' => $snapshot, 'context_version' => $row->context_version + 1])) {
            throw new IdentityException('context_changed', 409);
        }
        $request->session()->regenerate();
        $this->notifications->afterCommit($row->getConnection(), new ContextSelected($this->config->context()->name(), $row->subject, $selection['organizationId'] ?? null, $selection['roleId'] ?? null, $row->context_version + 1));
    }

    public function principal(Request $request, bool $fresh = false): Principal
    {
        $row = $this->requireSession($request);
        if (($row->selection['selected'] ?? false) !== true) {
            throw new IdentityException('context_required', 409);
        }
        if (! $fresh && is_array($row->snapshot) && strtotime($row->snapshot['expires_at'] ?? '') > time()) {
            $this->assertUnchanged($row);

            return new Principal($row->snapshot);
        }
        $selection = $row->selection;
        unset($selection['selected']);
        $snapshot = $this->authorization->snapshot($this->tokens($row)['access_token'], $row->subject, $row->sid, $selection);
        $this->assertUnchanged($row);
        if (! $this->sessions->publish($row, ['snapshot' => $snapshot])) {
            throw new IdentityException('context_changed', 409);
        }

        return new Principal($snapshot);
    }

    public function logout(Request $request, bool $central = false): ?string
    {
        $row = $this->sessions->find($this->id($request));
        if ($row) {
            $this->end($row);
        }
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        if ($row) {
            try {
                $tokens = $this->tokens($row);
                $this->http->form('/api/auth/oauth2/revoke', ['token' => $tokens['refresh_token'] ?? $tokens['access_token'], 'token_type_hint' => isset($tokens['refresh_token']) ? 'refresh_token' : 'access_token']);
            } catch (Throwable) { /* Local deletion is authoritative; remote grants remain bounded by the provider. */
            }
        }
        if (! $central) {
            return null;
        }
        $state = $this->logins->create($request->session()->getId(), [], 'logout');

        return $this->oidc->centralLogoutUrl($state);
    }

    public function finishLogout(Request $request, string $state): void
    {
        $this->logins->consume($state, $request->session()->getId(), 'logout');
    }

    private function end(IdentitySession $row): void
    {
        if ($this->sessions->delete($row->id)) {
            $this->notifications->afterCommit($row->getConnection(), new LocalSessionEnded($this->config->context()->name(), $row->subject, $row->context_version));
        }
    }

    private function requireSession(Request $request): IdentitySession
    {
        return $this->current($request) ?? throw new IdentityException('sign_in_required', 401);
    }

    private function id(Request $request): ?string
    {
        if (! $request->hasSession()) {
            return null;
        }
        $id = $request->session()->get('identity.session');

        return is_string($id) ? $id : null;
    }

    private function tokens(IdentitySession $row): array
    {
        return $this->vault->open($row->token_vault, 'session:'.$row->id);
    }

    /** Observe existing deadlines without refreshing a token or extending activity. */
    public function live(IdentitySession $row): bool
    {
        return $row->expires_at->isFuture() && $row->started_at->addSeconds((int) $this->config->value('local.absolute_seconds', 43200))->isFuture() && $row->last_activity_at->addSeconds((int) $this->config->value('local.idle_seconds', 1800))->isFuture();
    }

    private function assertUnchanged(IdentitySession $row): void
    {
        $current = $this->sessions->find($row->id);
        if (! $current || ! $this->live($current) || $current->context_version !== $row->context_version || $current->token_generation !== $row->token_generation) {
            throw new IdentityException('context_changed', 409);
        }
    }

    private function requireLiveIntent(array $intent): void
    {
        if (! is_int($intent['created_at'] ?? null) || now()->timestamp - $intent['created_at'] >= min(300, (int) $this->config->value('local.transaction_seconds', 300))) {
            throw new IdentityException('login_expired', 401);
        }
    }

    private function renew(object $lock): void
    {
        try {
            if ($lock->refresh(60)) {
                return;
            }
        } catch (Throwable) { /* An unsupported or unavailable lease cannot authorize publication. */
        }
        throw new IdentityException('session_busy', 503);
    }

    private function locked(string $id, callable $work): mixed
    {
        $lock = Cache::store($this->config->value('lock_store'))->lock('identity-refresh:'.$this->config->bindingHash().':'.$id, 60);
        try {
            return $lock->block(3, fn () => $work($lock));
        } catch (LockTimeoutException) {
            throw new IdentityException('session_busy', 503);
        }
    }
}
