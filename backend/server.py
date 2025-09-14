from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import hashlib
import jwt
import csv
import io
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI(title="Election System API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Enums
class ElectionStatus(str, Enum):
    NOT_STARTED = "not_started"
    ACTIVE = "active"
    ENDED = "ended"

# Database Models
class Student(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    index_number: str
    surname: str
    reference_number: str
    has_voted: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StudentCreate(BaseModel):
    index_number: str
    surname: str
    reference_number: str

class AdminUser(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Election(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    start_at: datetime
    end_at: datetime
    status: ElectionStatus = ElectionStatus.NOT_STARTED
    eligible_voters: int = 0
    total_votes: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ElectionCreate(BaseModel):
    name: str
    start_at: datetime
    end_at: datetime

class Position(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    election_id: str
    name: str
    order: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PositionCreate(BaseModel):
    name: str
    order: int = 0

class Candidate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    position_id: str
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CandidateCreate(BaseModel):
    name: str

class Poll(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    election_id: str
    question: str
    order: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PollCreate(BaseModel):
    question: str
    order: int = 0

class Vote(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    student_id: str
    election_id: str
    selections: Dict[str, Any]  # Store position_id: candidate_id and poll_id: answer
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Request/Response Models
class StudentLoginRequest(BaseModel):
    index_number: str
    pin: str

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_type: str  # "student" or "admin"
    user_id: str

class VoteRequest(BaseModel):
    selections: Dict[str, Any]

# Utility Functions
def generate_pin(surname: str, reference_number: str) -> str:
    """Generate PIN from surname + last 4 digits of reference number"""
    surname_clean = surname.lower().strip()
    last_four = reference_number[-4:] if len(reference_number) >= 4 else reference_number
    return surname_clean + last_four

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hashed

def create_access_token(data: dict) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc).timestamp() + (JWT_EXPIRATION_HOURS * 3600)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        user_type = payload.get("type")
        if user_id is None or user_type is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"user_id": user_id, "user_type": user_type}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_election():
    """Get the current active election"""
    election = await db.elections.find_one({"status": {"$in": ["not_started", "active"]}})
    if not election:
        raise HTTPException(status_code=404, detail="No active election found")
    return Election(**election)

async def update_election_status():
    """Update election status based on current time"""
    current_time = datetime.now(timezone.utc)
    
    # Update elections that should start
    await db.elections.update_many(
        {"start_at": {"$lte": current_time}, "status": "not_started"},
        {"$set": {"status": "active"}}
    )
    
    # Update elections that should end
    await db.elections.update_many(
        {"end_at": {"$lte": current_time}, "status": "active"},
        {"$set": {"status": "ended"}}
    )

# Authentication Endpoints
@api_router.post("/auth/student/login", response_model=LoginResponse)
async def student_login(request: StudentLoginRequest):
    """Student login with index number and PIN"""
    await update_election_status()
    
    # Find student by index number
    student_data = await db.students.find_one({"index_number": request.index_number})
    if not student_data:
        raise HTTPException(status_code=401, detail="Invalid index number or PIN")
    
    student = Student(**student_data)
    
    # Verify PIN
    expected_pin = generate_pin(student.surname, student.reference_number)
    if request.pin.lower() != expected_pin:
        raise HTTPException(status_code=401, detail="Invalid index number or PIN")
    
    # Create access token
    access_token = create_access_token({
        "sub": student.id,
        "type": "student",
        "index_number": student.index_number
    })
    
    return LoginResponse(
        access_token=access_token,
        user_type="student",
        user_id=student.id
    )

@api_router.post("/auth/admin/login", response_model=LoginResponse)
async def admin_login(request: AdminLoginRequest):
    """Admin login with username and password"""
    # Find admin user
    admin_data = await db.admin_users.find_one({"username": request.username})
    if not admin_data:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    admin = AdminUser(**admin_data)
    
    # Verify password
    if not verify_password(request.password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create access token
    access_token = create_access_token({
        "sub": admin.id,
        "type": "admin",
        "username": admin.username
    })
    
    return LoginResponse(
        access_token=access_token,
        user_type="admin",
        user_id=admin.id
    )

# Student Endpoints
@api_router.get("/student/status")
async def get_student_status(current_user: dict = Depends(get_current_user)):
    """Get student voting status and election info"""
    if current_user["user_type"] != "student":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    await update_election_status()
    
    try:
        election = await get_current_election()
    except HTTPException:
        return {"status": "no_election", "message": "No election scheduled"}
    
    student_data = await db.students.find_one({"id": current_user["user_id"]})
    student = Student(**student_data)
    
    current_time = datetime.now(timezone.utc)
    
    return {
        "election": election.dict(),
        "has_voted": student.has_voted,
        "current_time": current_time.isoformat(),
        "can_vote": election.status == "active" and not student.has_voted
    }

@api_router.get("/student/ballot")
async def get_ballot(current_user: dict = Depends(get_current_user)):
    """Get ballot for current election"""
    if current_user["user_type"] != "student":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    await update_election_status()
    election = await get_current_election()
    
    if election.status != "active":
        raise HTTPException(status_code=400, detail="Voting is not currently active")
    
    student_data = await db.students.find_one({"id": current_user["user_id"]})
    if Student(**student_data).has_voted:
        raise HTTPException(status_code=400, detail="You have already voted")
    
    # Get positions and candidates
    positions_data = await db.positions.find({"election_id": election.id}).sort("order", 1).to_list(None)
    positions = []
    
    for pos_data in positions_data:
        position = Position(**pos_data)
        candidates_data = await db.candidates.find({"position_id": position.id}).to_list(None)
        candidates = [Candidate(**c) for c in candidates_data]
        positions.append({
            "position": position.dict(),
            "candidates": [c.dict() for c in candidates]
        })
    
    # Get polls
    polls_data = await db.polls.find({"election_id": election.id}).sort("order", 1).to_list(None)
    polls = [Poll(**p).dict() for p in polls_data]
    
    return {
        "election": election.dict(),
        "positions": positions,
        "polls": polls
    }

@api_router.post("/student/vote")
async def submit_vote(vote_request: VoteRequest, current_user: dict = Depends(get_current_user)):
    """Submit student vote"""
    if current_user["user_type"] != "student":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    await update_election_status()
    election = await get_current_election()
    
    if election.status != "active":
        raise HTTPException(status_code=400, detail="Voting is not currently active")
    
    student_data = await db.students.find_one({"id": current_user["user_id"]})
    student = Student(**student_data)
    
    if student.has_voted:
        raise HTTPException(status_code=400, detail="You have already voted")
    
    # Create vote record
    vote = Vote(
        student_id=student.id,
        election_id=election.id,
        selections=vote_request.selections
    )
    
    # Save vote and mark student as voted
    await db.votes.insert_one(vote.dict())
    await db.students.update_one(
        {"id": student.id},
        {"$set": {"has_voted": True}}
    )
    
    # Update election vote count
    await db.elections.update_one(
        {"id": election.id},
        {"$inc": {"total_votes": 1}}
    )
    
    return {"message": "Vote submitted successfully"}

# Admin Endpoints
@api_router.get("/admin/dashboard")
async def get_admin_dashboard(current_user: dict = Depends(get_current_user)):
    """Get admin dashboard data"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    await update_election_status()
    
    # Get current election if exists
    election_data = await db.elections.find_one({"status": {"$in": ["not_started", "active"]}})
    election = Election(**election_data) if election_data else None
    
    # Get statistics
    total_students = await db.students.count_documents({})
    students_voted = await db.students.count_documents({"has_voted": True})
    
    return {
        "election": election.dict() if election else None,
        "statistics": {
            "total_students": total_students,
            "students_voted": students_voted,
            "students_not_voted": total_students - students_voted,
            "turnout_percentage": (students_voted / total_students * 100) if total_students > 0 else 0
        }
    }

@api_router.post("/admin/elections", response_model=Election)
async def create_election(election_data: ElectionCreate, current_user: dict = Depends(get_current_user)):
    """Create new election"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    # Check if there's already an active election
    existing = await db.elections.find_one({"status": {"$in": ["not_started", "active"]}})
    if existing:
        raise HTTPException(status_code=400, detail="There is already an active election")
    
    # Get total eligible voters
    total_students = await db.students.count_documents({})
    
    # Reset all students' voting status
    await db.students.update_many({}, {"$set": {"has_voted": False}})
    
    election = Election(
        **election_data.dict(),
        eligible_voters=total_students
    )
    
    await db.elections.insert_one(election.dict())
    return election

@api_router.post("/admin/elections/{election_id}/positions", response_model=Position)
async def create_position(election_id: str, position_data: PositionCreate, current_user: dict = Depends(get_current_user)):
    """Create position for election"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    position = Position(election_id=election_id, **position_data.dict())
    await db.positions.insert_one(position.dict())
    return position

@api_router.post("/admin/positions/{position_id}/candidates", response_model=Candidate)
async def create_candidate(position_id: str, candidate_data: CandidateCreate, current_user: dict = Depends(get_current_user)):
    """Create candidate for position"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    candidate = Candidate(position_id=position_id, **candidate_data.dict())
    await db.candidates.insert_one(candidate.dict())
    return candidate

@api_router.post("/admin/elections/{election_id}/polls", response_model=Poll)
async def create_poll(election_id: str, poll_data: PollCreate, current_user: dict = Depends(get_current_user)):
    """Create Yes/No poll for election"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    poll = Poll(election_id=election_id, **poll_data.dict())
    await db.polls.insert_one(poll.dict())
    return poll

@api_router.post("/admin/students/upload")
async def upload_students(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Upload students from CSV file"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    try:
        contents = await file.read()
        csv_data = contents.decode('utf-8')
        reader = csv.DictReader(io.StringIO(csv_data))
        
        students = []
        for row in reader:
            if not all(key in row for key in ['index_number', 'surname', 'reference_number']):
                raise HTTPException(status_code=400, detail="CSV must have columns: index_number, surname, reference_number")
            
            student = Student(
                index_number=row['index_number'].strip(),
                surname=row['surname'].strip(),
                reference_number=row['reference_number'].strip()
            )
            students.append(student.dict())
        
        if students:
            # Clear existing students and insert new ones
            await db.students.delete_many({})
            await db.students.insert_many(students)
        
        return {"message": f"Successfully uploaded {len(students)} students"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing CSV: {str(e)}")

@api_router.get("/admin/results/{election_id}")
async def get_election_results(election_id: str, current_user: dict = Depends(get_current_user)):
    """Get election results"""
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")
    
    election_data = await db.elections.find_one({"id": election_id})
    if not election_data:
        raise HTTPException(status_code=404, detail="Election not found")
    
    election = Election(**election_data)
    
    # Get all votes for this election
    votes = await db.votes.find({"election_id": election_id}).to_list(None)
    
    # Calculate results for positions
    positions_data = await db.positions.find({"election_id": election_id}).sort("order", 1).to_list(None)
    position_results = []
    
    for pos_data in positions_data:
        position = Position(**pos_data)
        candidates_data = await db.candidates.find({"position_id": position.id}).to_list(None)
        
        candidate_votes = {}
        for candidate_data in candidates_data:
            candidate = Candidate(**candidate_data)
            vote_count = sum(1 for vote in votes if vote.get("selections", {}).get(position.id) == candidate.id)
            candidate_votes[candidate.id] = {
                "name": candidate.name,
                "votes": vote_count,
                "percentage": (vote_count / len(votes) * 100) if votes else 0
            }
        
        position_results.append({
            "position": position.dict(),
            "candidates": candidate_votes
        })
    
    # Calculate results for polls
    polls_data = await db.polls.find({"election_id": election_id}).sort("order", 1).to_list(None)
    poll_results = []
    
    for poll_data in polls_data:
        poll = Poll(**poll_data)
        yes_votes = sum(1 for vote in votes if vote.get("selections", {}).get(poll.id) == "yes")
        no_votes = sum(1 for vote in votes if vote.get("selections", {}).get(poll.id) == "no")
        
        poll_results.append({
            "poll": poll.dict(),
            "yes_votes": yes_votes,
            "no_votes": no_votes,
            "yes_percentage": (yes_votes / len(votes) * 100) if votes else 0,
            "no_percentage": (no_votes / len(votes) * 100) if votes else 0
        })
    
    # Get students who didn't vote
    voted_student_ids = [vote["student_id"] for vote in votes]
    non_voters = await db.students.find({
        "id": {"$nin": voted_student_ids}
    }).to_list(None)
    
    return {
        "election": election.dict(),
        "statistics": {
            "eligible_voters": election.eligible_voters,
            "total_votes": len(votes),
            "turnout_percentage": (len(votes) / election.eligible_voters * 100) if election.eligible_voters > 0 else 0
        },
        "position_results": position_results,
        "poll_results": poll_results,
        "non_voters": [{"index_number": s["index_number"], "surname": s["surname"]} for s in non_voters]
    }

# Initialize admin user if not exists
async def init_admin():
    """Initialize default admin user"""
    admin_exists = await db.admin_users.find_one({"username": "admin"})
    if not admin_exists:
        admin = AdminUser(
            username="Bond442",
            password_hash=hash_password("Positiverockx..")  # Change this in production
        )
        await db.admin_users.insert_one(admin.dict())
        print("Default admin user created - username: admin, password: admin123")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    await init_admin()

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()