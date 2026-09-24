import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.connection import verify_schema, seed_defaults
from app.config import settings
from app.api import scans, chat, reports, auth, findings, tools, system, world_monitor, dashboard, schedules

app = FastAPI(
    title="CyberAgent API",
    description="Evidence-first security assessment platform. World Monitor and custom authorized targets run one engine; findings derive only from persisted observations.",
    version="1.0.0"
)

# Daemon thread for Phase 12 continuous assessment.  Started once at import
# (guarded by settings) and stopped at process exit; the event is kept for
# shutdown/cancellation hooks.
_scheduler_stop: threading.Event | None = None

# CORS is configuration-driven. Credentials are allowed because login
# sessions may be delivered via cookie; the origin list is explicit (no
# wildcard), which keeps credentialed CORS safe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB verification and seeding.
# The application assumes the database has already been migrated
# (alembic upgrade head). verify_schema fails loudly if tables are missing.
@app.on_event("startup")
def on_startup():
    verify_schema()
    seed_defaults()
    global _scheduler_stop
    from app.execution.schedule_loop import start_scheduler
    _scheduler_stop = start_scheduler()

# Include endpoints
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(chat.router)
app.include_router(reports.router)
app.include_router(findings.router)
app.include_router(tools.router)
app.include_router(system.router)
app.include_router(world_monitor.router)
app.include_router(dashboard.router)
app.include_router(schedules.router)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "app": "CyberAgent",
        "tagline": "Security Assesment Tool",
        "docs": "/docs",
        "simulation_mode": settings.simulation_mode
    }