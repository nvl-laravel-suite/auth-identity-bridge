<?php

declare(strict_types=1);

use IdentityPlatform\Laravel\Consumer\ConsumerCommand;
use IdentityPlatform\Laravel\Delegation\IdentityDelegatedAction;
use IdentityPlatform\Laravel\Delegation\IdentityDelegation;
use IdentityPlatform\Laravel\Exceptions\IdentityException;
use IdentityPlatform\Laravel\Models\IdentityInbox;
use IdentityPlatform\Laravel\Models\IdentityLogin;
use IdentityPlatform\Laravel\Models\IdentityProjectionOwner;
use IdentityPlatform\Laravel\Models\IdentitySession;
use IdentityPlatform\Laravel\Models\IdentityUser;
use IdentityPlatform\Laravel\Models\IdentityUserLink;
use IdentityPlatform\Laravel\Profiles\LocalProfile;
use IdentityPlatform\Laravel\Sync\ImportBinding;
use IdentityPlatform\Laravel\Sync\ImportEntry;
use IdentityPlatform\Laravel\Sync\ImportPage;
use IdentityPlatform\Laravel\Sync\ImportRun;
use IdentityPlatform\Laravel\Sync\UserImportLink;
use IdentityPlatform\Laravel\Sync\UserSyncBinding;
use IdentityPlatform\Laravel\Sync\UserSyncRequest;
use IdentityPlatform\Laravel\Sync\UserSyncState;
use IdentityPlatform\Laravel\Tests\TestCase;
use Illuminate\Database\Eloquent\MassAssignmentException;
use Illuminate\Database\Eloquent\Model;

uses(TestCase::class);

it('rejects unexpected authority attributes on internal persistence models', function (string $model): void {
    $wasStrict = Model::preventsSilentlyDiscardingAttributes();
    Model::preventSilentlyDiscardingAttributes();
    try {
        expect(fn () => new $model(['unrecognized_authority' => true]))
            ->toThrow(MassAssignmentException::class, 'unrecognized_authority');
    } finally {
        Model::preventSilentlyDiscardingAttributes($wasStrict);
    }
})->with([
    'IdentityInbox' => [IdentityInbox::class],
    'IdentityLogin' => [IdentityLogin::class],
    'IdentityProjectionOwner' => [IdentityProjectionOwner::class],
    'IdentitySession' => [IdentitySession::class],
    'IdentityUser' => [IdentityUser::class],
    'IdentityUserLink' => [IdentityUserLink::class],
    'LocalProfile' => [LocalProfile::class],
    'IdentityDelegation' => [IdentityDelegation::class],
    'IdentityDelegatedAction' => [IdentityDelegatedAction::class],
    'UserSyncBinding' => [UserSyncBinding::class],
    'UserSyncState' => [UserSyncState::class],
    'UserSyncRequest' => [UserSyncRequest::class],
    'UserImportLink' => [UserImportLink::class],
    'ImportRun' => [ImportRun::class],
    'ImportPage' => [ImportPage::class],
    'ImportBinding' => [ImportBinding::class],
    'ImportEntry' => [ImportEntry::class],
    'ConsumerCommand' => [ConsumerCommand::class],
]);

it('retains configured and per-model consumer connection names', function (): void {
    $previous = config('identity.connection');
    try {
        $model = (new IdentitySession)->setConnection('trusted-consumer');
        config(['identity.connection' => null]);
        expect($model->getConnectionName())->toBe('trusted-consumer');
        config(['identity.connection' => 'qualification']);
        expect($model->getConnectionName())->toBe('qualification');
    } finally {
        config(['identity.connection' => $previous]);
    }
});

it('refuses a non-string configured connection instead of returning it to Eloquent', function (): void {
    $previous = config('identity.connection');
    try {
        config(['identity.connection' => ['unrecognized-connection']]);
        expect(fn () => (new IdentitySession)->getConnectionName())
            ->toThrow(IdentityException::class, 'invalid_identity_configuration');
    } finally {
        config(['identity.connection' => $previous]);
    }
});
