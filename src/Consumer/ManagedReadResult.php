<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Consumer;

use JsonSerializable;
use LogicException;

/** Current field values and writableFields display hints; never write authority. */
final readonly class ManagedReadResult implements JsonSerializable
{
    /** @param array{id: non-empty-string, version: positive-int, fields: array<array-key, mixed>, writableFields: list<non-empty-string>}|null $data */
    public function __construct(public string $status, public ?array $data = null, public ?ManagedFailure $error = null) {}

    /** @return array{status: 'failed', error: ManagedFailure|null}|array{status: 'read', data: array<array-key, mixed>} */
    public function jsonSerialize(): array
    {
        if ($this->status !== 'read') {
            return ['status' => 'failed', 'error' => $this->error];
        }
        $data = $this->data ?? throw new LogicException('A managed read result requires read data.');
        $fields = $data['fields'];
        if (isset($fields['socialLinks']) && is_array($fields['socialLinks'])) {
            $fields['socialLinks'] = (object) $fields['socialLinks'];
        }
        $data['fields'] = (object) $fields;

        return ['status' => 'read', 'data' => $data];
    }
}
