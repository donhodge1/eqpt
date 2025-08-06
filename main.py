# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta, date
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from config import settings
from models import Base, User, Tool, Rental, UserRole, ToolCategory, RentalStatus, SessionLocal, engine, init_db

# Create tables and seed data
init_db()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, use settings.BACKEND_CORS_ORIGINS_LIST
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/login")


# Pydantic models for requests/responses
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole

    class Config:
        from_attributes = True


class ToolCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: ToolCategory
    daily_rate: float


class ToolUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[ToolCategory] = None
    daily_rate: Optional[float] = None
    is_available: Optional[bool] = None


class ToolResponse(BaseModel):
    id: int
    owner_id: int
    name: str
    description: Optional[str]
    category: ToolCategory
    daily_rate: float
    is_available: bool
    owner: UserResponse

    class Config:
        from_attributes = True


class RentalCreate(BaseModel):
    tool_id: int
    start_date: date
    end_date: date


class RentalResponse(BaseModel):
    id: int
    tool_id: int
    owner_id: int
    renter_id: int
    start_date: datetime
    end_date: datetime
    status: RentalStatus
    total_cost: float
    tool: ToolResponse
    renter: UserResponse

    class Config:
        from_attributes = True


class ToolAvailability(BaseModel):
    tool_id: int
    tool_name: str
    available_dates: List[date]
    booked_dates: List[dict]  # {start_date, end_date, renter_name}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user


# Routes

@app.get("/")
def root():
    return {"message": "Community Tool Rental API", "version": settings.APP_VERSION}


# Authentication
@app.post(f"{settings.API_V1_STR}/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post(f"{settings.API_V1_STR}/register", response_model=UserResponse)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create new user
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        full_name=user.full_name,
        role=UserRole.USER
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get(f"{settings.API_V1_STR}/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# Tools
@app.get(f"{settings.API_V1_STR}/tools", response_model=List[ToolResponse])
async def list_tools(
        category: Optional[ToolCategory] = None,
        available_only: bool = True,
        owner_id: Optional[int] = None,
        skip: int = 0,
        limit: int = settings.DEFAULT_LIMIT,
        db: Session = Depends(get_db)
):
    query = db.query(Tool)

    if category:
        query = query.filter(Tool.category == category)
    if available_only:
        query = query.filter(Tool.is_available == True)
    if owner_id:
        query = query.filter(Tool.owner_id == owner_id)

    tools = query.offset(skip).limit(limit).all()
    return tools


@app.get(f"{settings.API_V1_STR}/tools/{{tool_id}}", response_model=ToolResponse)
async def get_tool(tool_id: int, db: Session = Depends(get_db)):
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool


@app.post(f"{settings.API_V1_STR}/tools", response_model=ToolResponse)
async def create_tool(
        tool: ToolCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    db_tool = Tool(
        owner_id=current_user.id,
        name=tool.name,
        description=tool.description,
        category=tool.category,
        daily_rate=tool.daily_rate,
        is_available=True
    )
    db.add(db_tool)
    db.commit()
    db.refresh(db_tool)
    return db_tool


@app.put(f"{settings.API_V1_STR}/tools/{{tool_id}}", response_model=ToolResponse)
async def update_tool(
        tool_id: int,
        tool_update: ToolUpdate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Only owner can update their tool
    if tool.owner_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    for field, value in tool_update.dict(exclude_unset=True).items():
        setattr(tool, field, value)

    db.commit()
    db.refresh(tool)
    return tool


@app.delete(f"{settings.API_V1_STR}/tools/{{tool_id}}")
async def delete_tool(
        tool_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Only owner can delete their tool
    if tool.owner_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Check if tool has active rentals
    active_rentals = db.query(Rental).filter(
        Rental.tool_id == tool_id,
        Rental.status.in_([RentalStatus.PENDING, RentalStatus.ACTIVE])
    ).first()

    if active_rentals:
        raise HTTPException(status_code=400, detail="Cannot delete tool with active rentals")

    db.delete(tool)
    db.commit()
    return {"message": "Tool deleted successfully"}


# Tool Availability
@app.get(f"{settings.API_V1_STR}/tools/{{tool_id}}/availability", response_model=ToolAvailability)
async def get_tool_availability(
        tool_id: int,
        start_date: date,
        end_date: date,
        db: Session = Depends(get_db)
):
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Get all rentals for this tool in the date range
    rentals = db.query(Rental).filter(
        Rental.tool_id == tool_id,
        Rental.status.in_([RentalStatus.PENDING, RentalStatus.ACTIVE]),
        Rental.end_date >= start_date,
        Rental.start_date <= end_date
    ).all()

    # Calculate available and booked dates
    all_dates = []
    current = start_date
    while current <= end_date:
        all_dates.append(current)
        current += timedelta(days=1)

    booked_dates = []
    booked_days = set()

    for rental in rentals:
        rental_start = rental.start_date.date() if isinstance(rental.start_date, datetime) else rental.start_date
        rental_end = rental.end_date.date() if isinstance(rental.end_date, datetime) else rental.end_date

        booked_dates.append({
            "start_date": rental_start,
            "end_date": rental_end,
            "renter_name": rental.renter.username
        })

        # Mark individual days as booked
        current = max(rental_start, start_date)
        while current <= min(rental_end, end_date):
            booked_days.add(current)
            current += timedelta(days=1)

    available_dates = [d for d in all_dates if d not in booked_days]

    return ToolAvailability(
        tool_id=tool.id,
        tool_name=tool.name,
        available_dates=available_dates,
        booked_dates=booked_dates
    )


# Rentals
@app.post(f"{settings.API_V1_STR}/rentals", response_model=RentalResponse)
async def create_rental(
        rental: RentalCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # Validate tool exists
    tool = db.query(Tool).filter(Tool.id == rental.tool_id).first()
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Can't rent your own tool
    if tool.owner_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot rent your own tool")

    # Check if tool is available for these dates
    overlapping_rentals = db.query(Rental).filter(
        Rental.tool_id == rental.tool_id,
        Rental.status.in_([RentalStatus.PENDING, RentalStatus.ACTIVE]),
        Rental.end_date >= rental.start_date,
        Rental.start_date <= rental.end_date
    ).first()

    if overlapping_rentals:
        raise HTTPException(status_code=400, detail="Tool not available for selected dates")

    # Calculate total cost
    rental_days = (rental.end_date - rental.start_date).days + 1
    total_cost = tool.daily_rate * rental_days

    # Create rental
    db_rental = Rental(
        tool_id=rental.tool_id,
        owner_id=tool.owner_id,
        renter_id=current_user.id,
        start_date=datetime.combine(rental.start_date, datetime.min.time()),
        end_date=datetime.combine(rental.end_date, datetime.min.time()),
        status=RentalStatus.PENDING,
        total_cost=total_cost
    )

    db.add(db_rental)
    db.commit()
    db.refresh(db_rental)
    return db_rental


@app.get(f"{settings.API_V1_STR}/rentals", response_model=List[RentalResponse])
async def list_rentals(
        status: Optional[RentalStatus] = None,
        as_owner: bool = False,
        as_renter: bool = True,
        skip: int = 0,
        limit: int = settings.DEFAULT_LIMIT,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    query = db.query(Rental)

    # Filter by user role
    if as_owner and not as_renter:
        query = query.filter(Rental.owner_id == current_user.id)
    elif as_renter and not as_owner:
        query = query.filter(Rental.renter_id == current_user.id)
    elif as_owner and as_renter:
        query = query.filter(
            (Rental.owner_id == current_user.id) | (Rental.renter_id == current_user.id)
        )

    if status:
        query = query.filter(Rental.status == status)

    rentals = query.order_by(Rental.created_at.desc()).offset(skip).limit(limit).all()
    return rentals


@app.get(f"{settings.API_V1_STR}/rentals/active", response_model=List[RentalResponse])
async def list_active_rentals(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    today = datetime.now().date()
    rentals = db.query(Rental).filter(
        Rental.status == RentalStatus.ACTIVE,
        Rental.start_date <= today,
        Rental.end_date >= today,
        (Rental.owner_id == current_user.id) | (Rental.renter_id == current_user.id)
    ).all()
    return rentals


@app.put(f"{settings.API_V1_STR}/rentals/{{rental_id}}/status")
async def update_rental_status(
        rental_id: int,
        status: RentalStatus,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    rental = db.query(Rental).filter(Rental.id == rental_id).first()
    if not rental:
        raise HTTPException(status_code=404, detail="Rental not found")

    # Only owner can approve/reject, both can cancel
    if status in [RentalStatus.ACTIVE, RentalStatus.COMPLETED]:
        if rental.owner_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only owner can approve/complete rentals")
    elif status == RentalStatus.CANCELLED:
        if rental.owner_id != current_user.id and rental.renter_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized")

    rental.status = status

    # If completing, make tool available again
    if status == RentalStatus.COMPLETED:
        tool = db.query(Tool).filter(Tool.id == rental.tool_id).first()
        tool.is_available = True

    db.commit()
    return {"message": f"Rental status updated to {status}"}


# Categories
@app.get(f"{settings.API_V1_STR}/categories")
async def list_categories():
    return [{"value": cat.value, "label": cat.value.replace("_", " ").title()} for cat in ToolCategory]


# My Tools (owner dashboard)
@app.get(f"{settings.API_V1_STR}/my-tools", response_model=List[ToolResponse])
async def list_my_tools(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    tools = db.query(Tool).filter(Tool.owner_id == current_user.id).all()
    return tools


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)