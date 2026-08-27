import bcrypt

from shared.database.postgres import SessionLocal
from shared.models.base import Base
from shared.models.admin_user import AdminUser
from shared.database.postgres import engine

Base.metadata.create_all(bind=engine)

db = SessionLocal()

username = "admin"
password = "admin123"

existing = (
    db.query(AdminUser)
    .filter(AdminUser.username == username)
    .first()
)

if existing:

    print("Admin user already exists")

else:

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    user = AdminUser(
        username=username,
        password_hash=password_hash
    )

    db.add(user)

    db.commit()

    print("Admin user created")

db.close()