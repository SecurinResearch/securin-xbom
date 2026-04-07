"""testssl.sh wrapper for live TLS scanning (Layer 3).

Protocol, vulnerability, and certificate IDs loaded from rules/tls.yaml.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

import yaml

from xbom.models import ScanConfig
from xbom.utils.subprocess import find_tool, run

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent / "rules"
_tls_config: dict[str, Any] | None = None


def _load_tls_config() -> dict[str, Any]:
    global _tls_config
    if _tls_config is None:
        with open(_RULES_DIR / "tls.yaml") as f:
            _tls_config = yaml.safe_load(f)
    return _tls_config


def run_tls_scan(live_url: str, config: ScanConfig) -> list[dict[str, Any]]:
    """Run testssl.sh against a live URL and return CycloneDX components.

    Parses JSON output for protocols, cipher suites, certificates, and
    known vulnerabilities (BEAST, POODLE, Heartbleed, etc.).
    """
    testssl_path = find_tool("testssl.sh")
    if not testssl_path:
        # Also try without .sh extension
        testssl_path = find_tool("testssl")
        if not testssl_path:
            logger.warning("testssl.sh not installed, skipping TLS scan")
            return []

    tls_cfg = _load_tls_config()
    vuln_ids = set(tls_cfg["vuln_ids"])
    protocol_ids: dict[str, tuple[str, str, bool]] = {
        k: (v[0], v[1], v[2]) for k, v in tls_cfg["protocol_ids"].items()
    }
    cert_ids = set(tls_cfg["cert_ids"])

    json_file = tempfile.mktemp(suffix=".json")

    cmd = [
        testssl_path,
        "--jsonfile", json_file,
        "--quiet",
        "--color", "0",
        "--warnings", "off",
        live_url,
    ]

    result = run(cmd, timeout=180, verbose=config.verbose)

    if result.returncode not in (0, 1):
        logger.error("testssl.sh failed (exit %d): %s", result.returncode, result.stderr[:200])
        _cleanup(json_file)
        return []

    try:
        with open(json_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error("Failed to read testssl.sh output: %s", e)
        _cleanup(json_file)
        return []

    _cleanup(json_file)

    # Handle both array and object formats
    entries = data if isinstance(data, list) else data.get("scanResult", [{}])[0].get("serverDefaults", [])
    if isinstance(entries, dict):
        entries = [entries]

    components: list[dict[str, Any]] = []
    cert_data: dict[str, str] = {}
    vulnerabilities: list[str] = []

    for entry in entries:
        entry_id = entry.get("id", "")
        finding = entry.get("finding", "")
        severity = entry.get("severity", "OK")

        # Protocol entries
        if entry_id in protocol_ids:
            proto_name, version, is_deprecated = protocol_ids[entry_id]
            is_offered = "offered" in finding.lower() and "not offered" not in finding.lower()
            if is_offered:
                comp = _build_protocol_component(proto_name, version, is_deprecated, live_url)
                components.append(comp)

        # Certificate entries
        elif entry_id in cert_ids:
            cert_data[entry_id] = finding

        # Cipher suite entries
        elif entry_id.startswith("cipher_") or entry_id.startswith("cipherorder_"):
            if severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                comp = _build_cipher_component(finding, severity, live_url)
                if comp:
                    components.append(comp)

        # Vulnerability entries
        elif entry_id in vuln_ids:
            is_vulnerable = severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN")
            if is_vulnerable:
                vulnerabilities.append(f"{entry_id}: {finding}")

    # Build certificate component if we have cert data
    if cert_data:
        cert_comp = _build_certificate_component(cert_data, live_url)
        if cert_comp:
            # Attach vulnerability findings to certificate
            if vulnerabilities:
                cert_comp["properties"].append({
                    "name": "xbom:crypto:tls_vulnerabilities",
                    "value": "; ".join(vulnerabilities),
                })
            components.append(cert_comp)

    logger.info("testssl.sh found %d TLS components from %s", len(components), live_url)
    return components


def _build_protocol_component(
    name: str, version: str, is_deprecated: bool, url: str
) -> dict[str, Any]:
    """Build a CycloneDX component for a TLS/SSL protocol."""
    comp: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": f"{name} {version}",
        "description": f"{name} {version} offered by {url}",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": name.lower(),
                "version": version,
            },
        },
        "properties": [
            {"name": "xbom:crypto:detected", "value": "true"},
            {"name": "xbom:crypto:scanner", "value": "testssl"},
            {"name": "xbom:crypto:target_url", "value": url},
            {"name": "xbom:crypto:asset_type", "value": "protocol"},
        ],
    }

    if is_deprecated:
        comp["properties"].append({"name": "xbom:crypto:weakness", "value": "deprecated_protocol"})

    return comp


def _build_cipher_component(
    cipher_name: str, severity: str, url: str
) -> dict[str, Any] | None:
    """Build a CycloneDX component for a weak cipher suite."""
    if not cipher_name or len(cipher_name) < 3:
        return None

    weakness = "insecure_cipher_suite" if severity in ("HIGH", "CRITICAL") else ""

    return {
        "type": "cryptographic-asset",
        "name": cipher_name.strip(),
        "description": f"Cipher suite offered by {url}",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "ae",
            },
        },
        "properties": [
            {"name": "xbom:crypto:detected", "value": "true"},
            {"name": "xbom:crypto:scanner", "value": "testssl"},
            {"name": "xbom:crypto:target_url", "value": url},
            {"name": "xbom:crypto:asset_type", "value": "cipher-suite"},
            {"name": "xbom:crypto:severity", "value": severity.lower()},
            *([{"name": "xbom:crypto:weakness", "value": weakness}] if weakness else []),
        ],
    }


def _build_certificate_component(
    cert_data: dict[str, str], url: str
) -> dict[str, Any] | None:
    """Build a CycloneDX component for a TLS certificate."""
    cn = cert_data.get("cert_CN", "unknown")
    issuer = cert_data.get("cert_issuerCN", "")
    not_before = cert_data.get("cert_notBefore", "")
    not_after = cert_data.get("cert_notAfter", "")
    sig_algo = cert_data.get("cert_signatureAlgorithm", "")
    key_size = cert_data.get("cert_keySize", "")

    cert_props: dict[str, Any] = {}
    if cn:
        cert_props["subjectName"] = cn
    if issuer:
        cert_props["issuerName"] = issuer
    if not_before:
        cert_props["notValidBefore"] = not_before
    if not_after:
        cert_props["notValidAfter"] = not_after
    if sig_algo:
        cert_props["signatureAlgorithmRef"] = sig_algo

    comp: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": f"Certificate: {cn}",
        "description": f"TLS certificate for {url}",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": cert_props,
        },
        "properties": [
            {"name": "xbom:crypto:detected", "value": "true"},
            {"name": "xbom:crypto:scanner", "value": "testssl"},
            {"name": "xbom:crypto:target_url", "value": url},
            {"name": "xbom:crypto:asset_type", "value": "certificate"},
        ],
    }

    # Flag weak key sizes
    weaknesses = []
    if key_size:
        comp["properties"].append({"name": "xbom:crypto:key_size", "value": key_size})
        if "RSA" in key_size:
            try:
                bits = int("".join(c for c in key_size if c.isdigit()))
                if bits < 2048:
                    weaknesses.append("small_key_size")
            except ValueError:
                pass

    # Flag weak signature algorithms
    if sig_algo:
        comp["properties"].append({"name": "xbom:crypto:signature_algorithm", "value": sig_algo})
        sig_lower = sig_algo.lower()
        if "md5" in sig_lower or "sha1" in sig_lower:
            weaknesses.append("weak_algorithm")

    if weaknesses:
        comp["properties"].append({
            "name": "xbom:crypto:weakness",
            "value": ",".join(weaknesses),
        })

    return comp


def _cleanup(path: str) -> None:
    """Remove temporary file if it exists."""
    import contextlib

    with contextlib.suppress(OSError):
        Path(path).unlink(missing_ok=True)
