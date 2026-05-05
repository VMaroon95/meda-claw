"""
meda-claw v4.0 Governance Fabric
Shadow Agent Discovery Probe
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


MEDACLAW_DIR = Path.home() / ".medaclaw"

AGENT_PORTS = [
    11434,  # Ollama
    1234,   # LM Studio
    8080,
    8000,
    3000,
    7860,   # Gradio
    8888,   # Jupyter
    5000,
    8501,   # Streamlit
    4000,
    4200,
    9000,
    8200,   # Vault / misc
    50051,  # gRPC
]


@dataclass
class AgentEndpoint:
    host: str
    port: int
    service_name: str
    fingerprint: str
    is_secured: bool
    response_time_ms: float
    discovered_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class DiscoveryProbe:
    def __init__(self):
        MEDACLAW_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tcp_connect(self, host: str, port: int, timeout: float) -> Optional[float]:
        """Returns response time in ms, or None if connection failed."""
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                elapsed = (time.monotonic() - start) * 1000
                return round(elapsed, 2)
        except (OSError, socket.timeout):
            return None

    def _http_fingerprint(
        self, host: str, port: int, timeout: float
    ) -> tuple[str, bool, str]:
        """
        Returns (service_name, is_secured, fingerprint) via HTTP GET /.
        Falls back to generic names on failure.
        """
        url = f"http://{host}:{port}/"
        service_name = "unknown"
        fingerprint = ""
        is_secured = False

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "meda-claw-discovery/4.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(512).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                fingerprint = body[:128].strip()

                # Fingerprint well-known services
                body_lower = body.lower()
                server_header = headers.get("server", "").lower()
                content_type = headers.get("content-type", "").lower()

                if "ollama" in body_lower or port == 11434:
                    service_name = "ollama"
                elif "lm studio" in body_lower or port == 1234:
                    service_name = "lm-studio"
                elif "gradio" in body_lower or port == 7860:
                    service_name = "gradio"
                elif "jupyter" in body_lower or port == 8888:
                    service_name = "jupyter"
                elif "streamlit" in body_lower or port == 8501:
                    service_name = "streamlit"
                elif "grpc" in body_lower or port == 50051:
                    service_name = "grpc"
                elif server_header:
                    service_name = server_header.split("/")[0][:32]
                else:
                    service_name = f"http-service-{port}"

                # Heuristic: check for auth headers or HTTPS redirect
                if headers.get("www-authenticate") or headers.get("authorization"):
                    is_secured = True

        except urllib.error.HTTPError as exc:
            # 401/403 means secured
            if exc.code in (401, 403):
                is_secured = True
                service_name = f"http-service-{port}"
                fingerprint = f"HTTP {exc.code}"
            else:
                service_name = f"http-service-{port}"
                fingerprint = f"HTTP {exc.code}"
        except Exception:
            service_name = f"tcp-service-{port}"
            fingerprint = "tcp-only"

        return service_name, is_secured, fingerprint

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, host: str = "127.0.0.1", timeout: float = 1.0) -> List[AgentEndpoint]:
        endpoints: List[AgentEndpoint] = []
        for port in AGENT_PORTS:
            response_time = self._tcp_connect(host, port, timeout)
            if response_time is None:
                continue
            service_name, is_secured, fingerprint = self._http_fingerprint(
                host, port, timeout
            )
            endpoints.append(
                AgentEndpoint(
                    host=host,
                    port=port,
                    service_name=service_name,
                    fingerprint=fingerprint,
                    is_secured=is_secured,
                    response_time_ms=response_time,
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        return endpoints

    def posture_score(self, endpoints: List[AgentEndpoint]) -> int:
        """
        0-100 exposure score: higher = more exposed.
        - Base: 10 points per open port (capped at 50)
        - +5 per unsecured endpoint
        - Bonus: if > 5 ports open, +10 for excessive exposure
        """
        if not endpoints:
            return 0
        port_score = min(len(endpoints) * 10, 50)
        unsecured = sum(1 for e in endpoints if not e.is_secured)
        unsecured_score = unsecured * 5
        excess_score = 10 if len(endpoints) > 5 else 0
        return min(port_score + unsecured_score + excess_score, 100)

    def generate_report(self, endpoints: List[AgentEndpoint]) -> dict:
        score = self.posture_score(endpoints)
        if score >= 70:
            risk_level = "HIGH"
        elif score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        unsecured = [e for e in endpoints if not e.is_secured]
        secured = [e for e in endpoints if e.is_secured]

        recommendations = []
        if unsecured:
            recommendations.append(
                f"Secure {len(unsecured)} unsecured endpoint(s) with authentication."
            )
        if len(endpoints) > 5:
            recommendations.append(
                "Reduce attack surface: disable unused agent services."
            )
        if any(e.port == 11434 for e in unsecured):
            recommendations.append(
                "Ollama is exposed without auth — restrict to localhost or add a reverse proxy."
            )
        if any(e.port == 8888 for e in unsecured):
            recommendations.append(
                "Jupyter is exposed without auth — enable token/password authentication."
            )
        if not recommendations:
            recommendations.append("No immediate recommendations — posture looks healthy.")

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "host_scanned": endpoints[0].host if endpoints else "127.0.0.1",
            "summary": {
                "total_open_ports": len(endpoints),
                "secured": len(secured),
                "unsecured": len(unsecured),
                "posture_score": score,
            },
            "risk_level": risk_level,
            "endpoints": [e.to_dict() for e in endpoints],
            "recommendations": recommendations,
        }

    def save_report(self, report: dict, path: Optional[str] = None) -> str:
        if path is None:
            path = str(
                MEDACLAW_DIR
                / f"discovery_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.json"
            )
        Path(path).write_text(json.dumps(report, indent=2))
        return path
