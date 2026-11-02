<?php

declare(strict_types=1);

namespace IdentityPlatform\Laravel\Support;

/** Shared display/profile facts; these values never grant application authority. */
final class SharedProfile
{
    public const FIELDS = ['timezone', 'accountType', 'phone', 'organizationName', 'position', 'bio', 'dateOfBirth', 'gender', 'country', 'socialLinks', 'profileCompleted'];

    /** @param array<array-key, mixed> $profile */
    public static function valid(array $profile): bool
    {
        if (array_diff(self::FIELDS, array_keys($profile)) !== []) {
            return false;
        }
        if (! (self::text($profile['timezone'], 64) && $profile['timezone'] !== '' && in_array($profile['timezone'], timezone_identifiers_list(\DateTimeZone::ALL_WITH_BC), true)
            && in_array($profile['accountType'], ['individual', 'company'], true) && is_bool($profile['profileCompleted']))) {
            return false;
        }
        foreach (['phone' => 32, 'organizationName' => 160, 'position' => 120, 'bio' => 2000] as $field => $limit) {
            if (! ($profile[$field] === null || self::text($profile[$field], $limit))) {
                return false;
            }
        }
        $birth = $profile['dateOfBirth'];
        if (! ($birth === null || (is_string($birth) && preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $birth, $parts) === 1 && checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]) && $birth <= gmdate('Y-m-d')))) {
            return false;
        }
        if (! ($profile['gender'] === null || in_array($profile['gender'], ['male', 'female', 'other', 'prefer_not_to_say'], true))) {
            return false;
        }
        if (! ($profile['country'] === null || (is_string($profile['country']) && in_array($profile['country'], explode(' ', 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'), true)))) {
            return false;
        }
        $links = $profile['socialLinks'];
        if (! ($links === null || (is_array($links) && ($links === [] || ! array_is_list($links)) && count($links) <= 20))) {
            return false;
        }
        foreach ($links ?? [] as $key => $url) {
            if (! (self::text((string) $key, 64) && (string) $key !== '' && self::httpsUrl($url, 2048))) {
                return false;
            }
        }

        return true;
    }

    private static function text(mixed $value, int $maximum): bool
    {
        return is_string($value) && mb_check_encoding($value, 'UTF-8') && mb_strlen($value) <= $maximum && ! str_contains($value, "\0");
    }

    private static function httpsUrl(mixed $value, int $maximum): bool
    {
        $parts = is_string($value) ? parse_url($value) : false;

        return is_string($value) && strlen($value) <= $maximum && filter_var($value, FILTER_VALIDATE_URL) !== false && $parts
            && ($parts['scheme'] ?? null) === 'https' && ! isset($parts['user']) && ! isset($parts['pass']) && ! preg_match('/[\\x00-\\x20\\x7f]/', $value);
    }
}
