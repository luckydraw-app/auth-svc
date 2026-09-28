import os
import jwt
import bcrypt
from dotenv import load_dotenv

from datetime import datetime, timedelta

from flask import Flask, jsonify, request
from flask_restx import Api, Resource, fields
from prometheus_client import generate_latest
from sqlalchemy.orm import Session

from shared.database.postgres import SessionLocal, engine
from shared.models.base import Base
from shared.models.admin_user import AdminUser

from shared.telemetry.tracing import setup_tracing

from shared.telemetry.metrics import (
    login_success_total,
    login_failure_total
)

from shared.telemetry.logger import (
    get_logger,
    log_with_trace
)

from flask import Response

load_dotenv()

Base.metadata.create_all(bind=engine)

app = Flask(__name__)

setup_tracing(
    app=app,
    service_name="auth-service",
    engine=engine
)

logger = get_logger(
    "auth-service"
)

api = Api(
    app,
    version="1.0",
    title="Auth Service",
    description="Authentication APIs",
    doc="/swagger"
)

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")

JWT_EXPIRATION_HOURS = int(
    os.getenv("JWT_EXPIRATION_HOURS", 24)
)

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "admin123"
)

login_model = api.model(
    "LoginRequest",
    {
        "username": fields.String(required=True),
        "password": fields.String(required=True)
    }
)

@app.route("/health")
def health():

    return jsonify({
        "status": "UP",
        "service": "auth-service"
    })

@app.route("/metrics")
def metrics():

    return Response(
        generate_latest(),
        mimetype="text/plain"
    )

def create_default_admin():

    db: Session = SessionLocal()

    try:

        existing_user = (
            db.query(AdminUser)
            .filter(
                AdminUser.username == ADMIN_USERNAME
            )
            .first()
        )

        if existing_user:

            log_with_trace(
                logger,
                "INFO",
                "Default admin already exists"
            )

            return

        password_hash = bcrypt.hashpw(
            ADMIN_PASSWORD.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        admin_user = AdminUser(
            username=ADMIN_USERNAME,
            password_hash=password_hash
        )

        db.add(admin_user)
        db.commit()

        log_with_trace(
            logger,
            "INFO",
            "Default admin created",
            username=ADMIN_USERNAME
        )

    finally:

        db.close()

@api.route('/auth/api/v1/login')
class Login(Resource):

    @api.expect(login_model)

    def post(self):

        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:

            log_with_trace(
                logger,
                "ERROR",
                "Username or password missing"
            )

            return {
                "message": "username and password required"
            }, 400

        db: Session = SessionLocal()

        try:

            user = (
                db.query(AdminUser)
                .filter(
                    AdminUser.username == username
                )
                .first()
            )

            if not user:

                login_failure_total.inc()

                log_with_trace(
                    logger,
                    "ERROR",
                    "Invalid username",
                    username=username
                )

                return {
                    "message": "Invalid credentials"
                }, 401

            valid = bcrypt.checkpw(
                password.encode("utf-8"),
                user.password_hash.encode("utf-8")
            )

            if not valid:

                login_failure_total.inc()

                log_with_trace(
                    logger,
                    "ERROR",
                    "Invalid password",
                    username=username
                )

                return {
                    "message": "Invalid credentials"
                }, 401

            payload = {
                "username": user.username,
                "exp": datetime.utcnow() + timedelta(
                    hours=JWT_EXPIRATION_HOURS
                )
            }

            token = jwt.encode(
                payload,
                JWT_SECRET,
                algorithm=JWT_ALGORITHM
            )

            login_success_total.inc()

            log_with_trace(
                logger,
                "INFO",
                "Login successful",
                username=username
            )

            return {
                "token": token
            }

        except Exception as ex:

            log_with_trace(
                logger,
                "ERROR",
                "Login failed",
                error=str(ex)
            )

            return {
                "message": str(ex)
            }, 500

        finally:

            db.close()

create_default_admin()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app.run(host="0.0.0.0", port=args.port)
