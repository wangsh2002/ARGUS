from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit


HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    flags=re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"\bCVE[\s_-]?(\d{4})[\s_-]?(\d{4,})\b", re.IGNORECASE)
ATTACK_PATTERN = re.compile(r"^T(\d{4})(?:[.\s_-]?(\d{3}))?$", re.IGNORECASE)
HASH_PATTERN = re.compile(
    r"^(?:(?:md5|sha-?1|sha-?256)\s*[:=]\s*)?([a-f0-9]{32,64})$",
    re.IGNORECASE,
)
ENDPOINT_PATTERN = re.compile(r"^\[?([0-9a-f:.]+)\]?:(\d{1,5})$", re.IGNORECASE)


@dataclass(frozen=True)
class CanonicalEntity:
    entity_type: str
    value_type: str
    canonical_value: str
    canonical_key: str
    label: str
    entity_id: str
    auto_create: bool = True

    def model_dump(self) -> dict:
        return asdict(self)


def canonicalize_observation(value: str, kind: str) -> CanonicalEntity | None:
    """Return a conservative, globally stable identity for strong entity types.

    This deliberately does not use fuzzy semantics. Values that cannot be
    normalized without changing their meaning stay report-local.
    """

    original = unicodedata.normalize("NFKC", value).strip()
    if not original:
        return None
    refanged = _refang(original).strip(" \t\r\n\"'`<>")
    normalized_kind = kind.strip().casefold()

    cve_match = CVE_PATTERN.fullmatch(refanged)
    if cve_match:
        canonical = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
        return _entity("CVE", "cve", canonical.casefold(), canonical)

    attack_match = ATTACK_PATTERN.fullmatch(refanged)
    if attack_match:
        canonical = f"T{attack_match.group(1)}"
        if attack_match.group(2):
            canonical += f".{attack_match.group(2)}"
        return _entity(
            "ATT&CK 技术",
            "attack-technique",
            canonical.casefold(),
            canonical,
        )

    hash_match = HASH_PATTERN.fullmatch(re.sub(r"\s+", "", refanged))
    if hash_match:
        digest = hash_match.group(1).lower()
        algorithm = HASH_LENGTHS.get(len(digest))
        if algorithm:
            return _entity("IOC/基础设施", algorithm, digest, digest)

    if normalized_kind in {"ioc", "infrastructure"}:
        url = _canonical_url(refanged)
        if url is not None:
            return _entity("IOC/基础设施", "url", url, url)

        endpoint = _canonical_endpoint(refanged)
        if endpoint is not None:
            return _entity("IOC/基础设施", "network-endpoint", endpoint, endpoint)

        ip = _canonical_ip(refanged)
        if ip is not None:
            value_type = "ipv4" if ipaddress.ip_address(ip).version == 4 else "ipv6"
            return _entity("IOC/基础设施", value_type, ip, ip)

        email = _canonical_email(refanged)
        if email is not None:
            return _entity("IOC/基础设施", "email", email, email)

        domain = _canonical_domain(refanged)
        if domain is not None:
            return _entity("IOC/基础设施", "domain", domain, domain)

    if normalized_kind in {"vulnerability"}:
        return None

    # Named software uses deterministic exact-name identity. Alias and fuzzy
    # merging remain separate review concerns.
    if normalized_kind in {"malware", "tool"} and _looks_like_name(refanged):
        normalized_name = _normalize_name(refanged)
        if normalized_name:
            return _entity(
                "恶意软件/工具",
                "software-name",
                normalized_name,
                refanged,
            )

    return None


def alias_key(value: str) -> str:
    return _normalize_name(_refang(value))


def _entity(
    entity_type: str,
    value_type: str,
    canonical_value: str,
    label: str,
    *,
    auto_create: bool = True,
) -> CanonicalEntity:
    canonical_key = f"{value_type}:{canonical_value}"
    digest = sha256(canonical_key.encode("utf-8")).hexdigest()[:20]
    return CanonicalEntity(
        entity_type=entity_type,
        value_type=value_type,
        canonical_value=canonical_value,
        canonical_key=canonical_key,
        label=label,
        entity_id=f"ENT-CANON-{digest}",
        auto_create=auto_create,
    )


def _refang(value: str) -> str:
    result = value
    result = re.sub(r"(?i)^hxxps(?=://)", "https", result)
    result = re.sub(r"(?i)^hxxp(?=://)", "http", result)
    result = result.replace("[.]", ".").replace("(.)", ".")
    result = result.replace("[:]", ":").replace("(:)", ":")
    return result


def _canonical_ip(value: str) -> str | None:
    candidate = value.strip().strip("[]")
    try:
        return ipaddress.ip_address(candidate).compressed.casefold()
    except ValueError:
        return None


def _canonical_endpoint(value: str) -> str | None:
    match = ENDPOINT_PATTERN.fullmatch(value.strip())
    if not match:
        return None
    host, raw_port = match.groups()
    try:
        port = int(raw_port)
        if not 0 < port <= 65535:
            return None
        canonical_host = ipaddress.ip_address(host).compressed.casefold()
    except ValueError:
        return None
    rendered_host = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    return f"{rendered_host}:{port}"


def _canonical_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".").casefold()
    if not DOMAIN_PATTERN.fullmatch(candidate):
        return None
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _canonical_email(value: str) -> str | None:
    if value.count("@") != 1:
        return None
    local, domain = value.rsplit("@", 1)
    canonical_domain = _canonical_domain(domain)
    if not local or canonical_domain is None:
        return None
    return f"{local}@{canonical_domain}"


def _canonical_url(value: str) -> str | None:
    if not re.match(r"(?i)^https?://", value):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if not host:
            return None
        canonical_host = _canonical_ip(host) or _canonical_domain(host)
        if canonical_host is None:
            return None
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    host_rendered = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    if port is not None and not default_port:
        host_rendered = f"{host_rendered}:{port}"
    if parsed.username is not None:
        credentials = parsed.username
        if parsed.password is not None:
            credentials += f":{parsed.password}"
        host_rendered = f"{credentials}@{host_rendered}"
    path = parsed.path or "/"
    return urlunsplit((scheme, host_rendered, path, parsed.query, parsed.fragment))


def _normalize_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", normalized)


def _looks_like_name(value: str) -> bool:
    if len(value) > 120:
        return False
    return not bool(
        re.search(
            r"\b(deploy(?:ment|s|ed|ing)?|execut(?:e|ion|es|ed|ing)|"
            r"download(?:s|ed|ing)?|collect(?:s|ed|ion|ing)?|"
            r"connect(?:s|ed|ion|ing)?|creat(?:e|es|ed|ion|ing)|"
            r"drop(?:s|ped|ping)?|launch(?:es|ed|ing)?|"
            r"部署|执行|下载|收集|连接|创建|投递)\b",
            value,
            flags=re.IGNORECASE,
        )
    )
