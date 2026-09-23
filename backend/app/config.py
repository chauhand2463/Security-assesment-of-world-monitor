"""Centralised application configuration.

Reads configuration from environment variables (optionally loaded from a
``.env`` file via python-dotenv).  Nothing in this module is secret by
construction -- real credentials/keys must never be placed here.

Environment variables consumed:
  DATABASE_URL   SQLAlchemy database URL.            Default: sqlite:///./cyberagent.db
  SIMULATION_MODE Whether scans run in simulation.    Default: false (real execution only)
  CORS_ORIGINS   Comma separated allowed CORS origins. Default: local dev Vite origins
  REDIS_URL      Broker URL (reserved for future Celery use). Default: redis://localhost:6379/0
  SESSION_TTL_HOURS  Login session lifetime in hours. Default: 12
  TOOL_PATH      Extra scanner binary directories (PATH-separated), merged
                 into the process PATH at import so scanners not on the
                 system PATH are still detected. Default: empty.
ADMIN_EMAIL    Bootstrap admin email. Only used when both ADMIN_EMAIL and
                  ADMIN_PASSWORD are set and ADMIN_DISABLED != "true".
   ADMIN_PASSWORD Bootstrap admin password (dev/self-host bootstrap only).
   ADMIN_DISABLED Set "true" to skip the bootstrap admin seeding.
   WORLD_MONITOR_BASE_URL     Base URL of the authorized World Monitor
                              deployment (health check root). Empty = not
                              configured. Never guessed or defaulted.
   WORLD_MONITOR_API_BASE_URL Optional API base path of the deployment.
   WORLD_MONITOR_OPENAPI_URL  Optional OpenAPI document URL of the deployment.
   WORLD_MONITOR_STALE_AFTER_SECONDS  Age (seconds) after which a World
                              Monitor probe result is surfaced as stale in
                              API payloads. Default: 3600. Staleness is a
                              surfaced fact, never an auto re-probe.
"""
import os

from dotenv import load_dotenv

# Load variables from a .env file (if present). Existing process environment
# variables always win because python-dotenv does not override by default.
load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./cyberagent.db")
        # Phase 7: scans execute real tools by default.  Simulation is an
        # explicit, operator-chosen mode for sandboxed environments only --
        # it must never be the silent default for a security platform.
        self.simulation_mode = _env_bool("SIMULATION_MODE", False)
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

        # Preserve only origins actually required by the current frontend.
        # CORS_ORIGINS overrides the development defaults when provided.
        # Vite picks the first free port starting at 5173, so local dev allows
        # the common fallback ports (5174, 5175) as well as the primary one.
        raw_origins = os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,"
            "http://localhost:5174,http://127.0.0.1:5174,"
            "http://localhost:5175,http://127.0.0.1:5175",
        )
        self.cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

        # Session lifetime in hours (fixed expiry; no sliding renewal).
        try:
            self.session_ttl_hours = int(os.getenv("SESSION_TTL_HOURS", "12"))
        except ValueError:
            self.session_ttl_hours = 12
        if self.session_ttl_hours < 1:
            self.session_ttl_hours = 12

        # Extra scanner binary directories (PATH-separated). These are merged
        # into the process PATH at import time by scanner_tools.refresh_tool_path()
        # so tools not on the system PATH can still be detected and executed.
        self.tool_path = [p.strip() for p in (os.getenv("TOOL_PATH", "") or "").split(os.pathsep) if p.strip()]

        # Bootstrap admin credentials. Never defaults to a real credential:
        # the admin is only created when *both* variables are explicitly set
        # and the bootstrap has not been disabled.
        self.admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        self.admin_password = os.getenv("ADMIN_PASSWORD", "")
        self.admin_enabled = (
            bool(self.admin_email)
            and bool(self.admin_password)
            and not _env_bool("ADMIN_DISABLED", False)
        )

        # World Monitor deployment configuration (Phase 8). Empty means "not
        # configured" -- the platform never guesses or fabricates these URLs.
        # Runtime truth comes only from these values plus live probes.
        self.world_monitor_base_url = (
            os.getenv("WORLD_MONITOR_BASE_URL", "").strip().rstrip("/") or None
        )
        self.world_monitor_api_base_url = (
            os.getenv("WORLD_MONITOR_API_BASE_URL", "").strip().rstrip("/") or None
        )
        self.world_monitor_openapi_url = (
            os.getenv("WORLD_MONITOR_OPENAPI_URL", "").strip().rstrip("/") or None
        )
        # How old a World Monitor probe result must be before it is surfaced as
        # stale in API payloads (seconds).  Staleness is a surfaced fact, never
        # an automatic decision to re-probe.
        try:
            self.world_monitor_stale_after_seconds = int(
                os.getenv("WORLD_MONITOR_STALE_AFTER_SECONDS", "3600")
            )
        except ValueError:
            self.world_monitor_stale_after_seconds = 3600


settings = Settings()