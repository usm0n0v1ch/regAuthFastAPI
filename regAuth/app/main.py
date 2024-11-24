from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import get_db, Base, engine
from .schemas import UserCreate, Token
from .utils import get_password_hash
from .auth import login_user
from .repository.user_repository import get_user_by_username, create_user

app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    create_user(db, user.username, hashed_password)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(user: UserCreate, db: Session = Depends(get_db)):
    return login_user(db, user.username, user.password)
