from __future__ import annotations

from flask import Flask

from backend.routes.announcements import bp as announcements_bp
from backend.routes.calendar import bp as calendar_bp
from backend.routes.groups import bp as groups_bp
from backend.routes.meetings import bp as meetings_bp
from backend.routes.messages import bp as messages_bp
from backend.routes.users import bp as users_bp
from backend.routes.E2ee import bp as e2ee_bp


def register_routes(app: Flask) -> None:
    app.register_blueprint(users_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(meetings_bp)
    app.register_blueprint(calendar_bp)
    app.register_blueprint(announcements_bp)
    app.register_blueprint(e2ee_bp)