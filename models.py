# models.py
from datetime import datetime
from enum import Enum
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func

Base = declarative_base()


# Enums
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"


class ToolCategory(str, Enum):
    CAMERA = "camera"
    MUSIC = "music"
    POWER_TOOLS = "power_tools"
    HAND_TOOLS = "hand_tools"
    GARDENING = "gardening"
    CONSTRUCTION = "construction"
    AUTOMOTIVE = "automotive"
    RESTAURANT = "restaurant"
    OTHER = "other"


class RentalStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# Database Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(SQLEnum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    owned_tools = relationship("Tool", back_populates="owner", foreign_keys="Tool.owner_id")
    rentals_as_renter = relationship("Rental", back_populates="renter", foreign_keys="Rental.renter_id")
    rentals_as_owner = relationship("Rental", back_populates="owner", primaryjoin="User.id==Rental.owner_id")


class Tool(Base):
    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(String)
    category = Column(SQLEnum(ToolCategory), nullable=False)
    daily_rate = Column(Float, nullable=False)
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    owner = relationship("User", back_populates="owned_tools", foreign_keys=[owner_id])
    rentals = relationship("Rental", back_populates="tool")


class Rental(Base):
    __tablename__ = "rentals"

    id = Column(Integer, primary_key=True, index=True)
    tool_id = Column(Integer, ForeignKey("tools.id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    renter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    status = Column(SQLEnum(RentalStatus), default=RentalStatus.PENDING)
    total_cost = Column(Float)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    tool = relationship("Tool", back_populates="rentals")
    owner = relationship("User", foreign_keys=[owner_id])
    renter = relationship("User", back_populates="rentals_as_renter", foreign_keys=[renter_id])


# Future: Groups (stubbed out)
class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# golden_thread.py - Quick test script
from passlib.context import CryptContext
from sqlalchemy.orm import Session

# Database setup
DATABASE_URL = "sqlite:///./toolrental.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password):
    return pwd_context.hash(password)


def init_db():
    """Create tables and seed with test data"""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # Check if we already have data
    if db.query(User).first():
        print("Database already initialized")
        return

    # Create test users
    admin = User(
        username="admin",
        email="admin@toolrental.com",
        hashed_password=get_password_hash("admin"),
        full_name="Admin User",
        role=UserRole.ADMIN
    )

    alice = User(
        username="alice",
        email="alice@example.com",
        hashed_password=get_password_hash("alice123"),
        full_name="Alice Johnson",
        role=UserRole.USER
    )

    bob = User(
        username="bob",
        email="bob@example.com",
        hashed_password=get_password_hash("bob123"),
        full_name="Bob Smith",
        role=UserRole.USER
    )

    db.add_all([admin, alice, bob])
    db.commit()

    # Create some tools owned by users
    drill = Tool(
        owner_id=alice.id,
        name="DeWalt Cordless Drill",
        description="20V MAX cordless drill with 2 batteries",
        category=ToolCategory.POWER_TOOLS,
        daily_rate=15.00
    )

    saw = Tool(
        owner_id=alice.id,
        name="Circular Saw",
        description="7-1/4 inch circular saw, great for wood cutting",
        category=ToolCategory.POWER_TOOLS,
        daily_rate=20.00
    )

    mower = Tool(
        owner_id=bob.id,
        name="Gas Lawn Mower",
        description="Self-propelled 21-inch mower",
        category=ToolCategory.GARDENING,
        daily_rate=25.00
    )

    wrench_set = Tool(
        owner_id=bob.id,
        name="Metric Wrench Set",
        description="Complete set from 8mm to 22mm",
        category=ToolCategory.HAND_TOOLS,
        daily_rate=5.00
    )

    db.add_all([drill, saw, mower, wrench_set])
    db.commit()

    # Create a sample rental
    rental = Rental(
        tool_id=drill.id,
        owner_id=alice.id,
        renter_id=bob.id,
        start_date=datetime.now(),
        end_date=datetime.now().replace(day=datetime.now().day + 3),
        status=RentalStatus.ACTIVE,
        total_cost=45.00  # 3 days * $15
    )

    db.add(rental)
    db.commit()
    db.close()

    print("Database initialized with test data!")
    print("Users: admin:admin, alice:alice123, bob:bob123")


def test_queries():
    """Test some basic queries"""
    # Ensure database is initialized
    init_db()

    db = SessionLocal()

    print("\n=== All Users ===")
    users = db.query(User).all()
    for user in users:
        print(f"{user.username} ({user.email}) - Role: {user.role}")

    print("\n=== All Tools ===")
    tools = db.query(Tool).all()
    for tool in tools:
        print(f"{tool.name} - ${tool.daily_rate}/day - Owner: {tool.owner.username}")

    print("\n=== Active Rentals ===")
    rentals = db.query(Rental).filter(Rental.status == RentalStatus.ACTIVE).all()
    for rental in rentals:
        print(f"{rental.renter.username} renting {rental.tool.name} from {rental.owner.username}")

    print("\n=== Alice's Tools ===")
    alice = db.query(User).filter(User.username == "alice").first()
    if alice:
        for tool in alice.owned_tools:
            print(f"- {tool.name} (${tool.daily_rate}/day)")

    db.close()


if __name__ == "__main__":
    init_db()
    test_queries()