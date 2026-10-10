
import os
from datetime import datetime, timedelta, timezone
from typing import Generator

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


# ==============================
# 1. CONFIGURATION
# ==============================

DATABASE_URL = "sqlite:///./app.db"

# Development fallback only. Set JWT_SECRET_KEY before deployment.
SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "dev-only-secret-change-before-deployment"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ==============================
# 2. DATABASE CONNECTION
# ==============================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


# ==============================
# 3. DATABASE TABLES
# ==============================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255))


class Item(Base):
    __tablename__ = "items"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500), default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))


Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==============================
# 4. PYDANTIC REQUEST SCHEMAS
# ==============================

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserResponse(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class ItemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)


class ItemUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class ItemResponse(BaseModel):
    id: int
    title: str
    description: str
    owner_id: int

    model_config = ConfigDict(from_attributes=True)


# ==============================
# 5. PASSWORD HASHING AND JWT
# ==============================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    return hashed.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        user_id = int(payload["sub"])
    except (
        jwt.InvalidTokenError,
        KeyError,
        ValueError,
        TypeError
    ):
        raise unauthorized

    user = db.get(User, user_id)

    if user is None:
        raise unauthorized

    return user


# ==============================
# 6. FASTAPI APPLICATION
# ==============================

app = FastAPI(
    title="FastAPI JWT Authentication Microservice",
    description=(
        "REST API with user registration, login, JWT authentication, "
        "SQLite persistence, and protected CRUD operations."
    ),
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "FastAPI JWT Microservice is running!",
        "documentation": "/docs"
    }


# ==============================
# 7. USER REGISTRATION
# ==============================

@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"]
)
def register_user(
    data: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = db.scalar(
        select(User).where(User.email == str(data.email))
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered"
        )

    user = User(
        email=str(data.email),
        password_hash=hash_password(data.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# ==============================
# 8. USER LOGIN
# ==============================

@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Authentication"]
)
def login_user(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # OAuth2PasswordRequestForm uses "username" for the email.
    user = db.scalar(
        select(User).where(User.email == form.username)
    )

    if user is None or not verify_password(
        form.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ==============================
# 9. CURRENT USER PROFILE
# ==============================

@app.get(
    "/auth/me",
    response_model=UserResponse,
    tags=["Authentication"]
)
def get_my_profile(
    user: User = Depends(get_current_user)
):
    return user


# ==============================
# 10. CREATE ITEM
# ==============================

@app.post(
    "/items",
    response_model=ItemResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Items CRUD"]
)
def create_item(
    data: ItemCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    item = Item(
        title=data.title,
        description=data.description,
        owner_id=user.id
    )

    db.add(item)
    db.commit()
    db.refresh(item)

    return item


# ==============================
# 11. READ ALL USER ITEMS
# ==============================

@app.get(
    "/items",
    response_model=list[ItemResponse],
    tags=["Items CRUD"]
)
def get_items(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    items = db.scalars(
        select(Item).where(Item.owner_id == user.id)
    ).all()

    return items


# ==============================
# 12. READ ONE ITEM
# ==============================

@app.get(
    "/items/{item_id}",
    response_model=ItemResponse,
    tags=["Items CRUD"]
)
def get_item(
    item_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    item = db.get(Item, item_id)

    if item is None or item.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )

    return item


# ==============================
# 13. UPDATE ITEM
# ==============================

@app.patch(
    "/items/{item_id}",
    response_model=ItemResponse,
    tags=["Items CRUD"]
)
def update_item(
    item_id: int,
    data: ItemUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    item = db.get(Item, item_id)

    if item is None or item.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )

    updates = data.model_dump(
        exclude_unset=True,
        exclude_none=True
    )

    for field, value in updates.items():
        setattr(item, field, value)

    db.commit()
    db.refresh(item)

    return item


# ==============================
# 14. DELETE ITEM
# ==============================

@app.delete(
    "/items/{item_id}",
    tags=["Items CRUD"]
)
def delete_item(
    item_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    item = db.get(Item, item_id)

    if item is None or item.owner_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )

    db.delete(item)
    db.commit()

    return {
        "message": "Item deleted successfully",
        "item_id": item_id
    }
