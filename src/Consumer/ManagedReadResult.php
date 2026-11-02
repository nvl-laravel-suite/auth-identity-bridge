<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use JsonSerializable;

/** Current field values and writableFields display hints; never write authority. */
final readonly class ManagedReadResult implements JsonSerializable
{
    public function __construct(public string $status, public ?array $data = null, public ?ManagedFailure $error = null) {}

    public function jsonSerialize(): array
    {
        if ($this->status !== 'read') {
            return ['status' => 'failed', 'error' => $this->error];
        }
        $data = $this->data;
        $fields = $data['fields'];
        if (isset($fields['socialLinks']) && is_array($fields['socialLinks'])) {
            $fields['socialLinks'] = (object) $fields['socialLinks'];
        }
        $data['fields'] = (object) $fields;

        return ['status' => 'read', 'data' => $data];
    }
}
