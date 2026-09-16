"""Value normalisation shared by ingest and enrich."""

from __future__ import annotations

from datetime import UTC, datetime

# AllFieldInfo and the MITRE columns both use this separator (ADR-0002 sections 6 and 8).
FIELD_SEPARATOR = " ¦ "

SYSTEM_ACCOUNTS = {
    "-",
    "",
    "system",
    "local service",
    "network service",
    "anonymous logon",
}


def normalize_host(computer: str) -> str:
    """Lower-case host name reduced to the first label of an FQDN."""
    return computer.strip().lower().split(".", 1)[0]


def normalize_user(user: str, domain: str | None = None) -> str:
    """Lower-case `domain\\user`, with machine and service accounts folded to `system`.

    Sysmon writes the account as one combined `DOMAIN\\name` string in its `User`
    field, while the Security log splits it across two fields. Both shapes arrive
    here, so the domain is separated first and the system-account test is applied
    to the bare account name. Without that split `NT AUTHORITY\\SYSTEM` would look
    like an ordinary user and would pull service activity into a person's group.
    """
    raw = user.strip().lower()
    realm = (domain or "").strip().lower()

    if "\\" in raw:
        prefix, _, name = raw.rpartition("\\")
        if prefix:
            realm = prefix
        raw = name

    if raw in SYSTEM_ACCOUNTS or raw.endswith("$"):
        return "system"
    if realm and realm != "-":
        return f"{realm}\\{raw}"
    return raw


def parse_timestamp(text: str, *, assume_utc: bool) -> datetime:
    """Parse a Hayabusa timestamp.

    Three shapes were measured in real output: six fractional digits, three
    fractional digits, and no fractional part at all, always with a `Z` suffix
    (ADR-0002 section 7). `fromisoformat` covers all three; a fixed strptime
    format would not.
    """
    raw = text.strip()
    if not raw:
        raise ValueError("empty timestamp")
    candidate = f"{raw[:-1]}+00:00" if raw.endswith(("Z", "z")) else raw
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        if not assume_utc:
            raise ValueError(
                f"timestamp {raw!r} has no UTC offset; "
                f"re-run Hayabusa with -U -O, or set ingest.assume_utc = true"
            )
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def split_multi_value(text: str) -> list[str]:
    """Split a MitreTactics / MitreTags / OtherTags cell into its values."""
    stripped = text.strip()
    if not stripped:
        return []
    return [part.strip() for part in stripped.split(FIELD_SEPARATOR) if part.strip()]


def parse_all_field_info(text: str) -> tuple[dict[str, str | list[str]], list[str]]:
    """Parse the AllFieldInfo cell into `{key: value}`.

    Chunks are separated by ` ¦ ` and each chunk splits on its first `: `.
    A field with an empty value arrives as `RuleName:` with no trailing space,
    because the separator consumed it, so that shape is handled explicitly.
    Anything else is reported instead of being dropped.
    """
    fields: dict[str, str | list[str]] = {}
    errors: list[str] = []
    if not text.strip():
        return fields, errors

    for chunk in text.split(FIELD_SEPARATOR):
        if not chunk:
            continue
        if ": " in chunk:
            key, value = chunk.split(": ", 1)
        elif chunk.endswith(":"):
            key, value = chunk[:-1], ""
        else:
            errors.append(f"field chunk without a key separator: {chunk[:80]!r}")
            continue

        key = key.strip()
        if not key:
            errors.append(f"field chunk with an empty key: {chunk[:80]!r}")
            continue

        if key in fields:
            existing = fields[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[key] = [existing, value]
        else:
            fields[key] = value

    return fields, errors
