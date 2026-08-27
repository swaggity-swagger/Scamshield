from app.database.base import Base
from app.database.session import engine
from app.models.user import User
from app.models.incident import Incident


def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("Database tables created successfully.")