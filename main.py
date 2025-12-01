from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, date, time, timedelta
from enum import Enum
from typing import Optional, List
from fastapi import Response

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    UploadFile,
    File,
    Form,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Text,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

from starlette.responses import StreamingResponse, FileResponse
import io
import csv
import os
import uuid


# =========================
# DB 설정 (SQLite 파일: attendance.db)
# =========================
SQLALCHEMY_DATABASE_URL = "sqlite:///./attendance.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 도면 파일 저장 폴더
UPLOAD_DIR = "uploads/drawings"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ✅ 하자 신고 사진 저장 폴더
ISSUE_UPLOAD_DIR = "uploads/issues"
os.makedirs(ISSUE_UPLOAD_DIR, exist_ok=True)


# =========================
# Enum 정의
# =========================
class Role(str, Enum):
    worker = "worker"    # 근로자(작업자)
    manager = "manager"  # 관리자


class Gender(str, Enum):
    male = "남"
    female = "여"
    other = "기타"


# =========================
# SQLAlchemy 테이블 정의
# =========================
class SiteTable(Base):
    """
    여러 '현장(커뮤니티)'를 구분하기 위한 테이블
    """
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)         # 현장 이름
    description = Column(Text, nullable=True)                  # 설명
    location = Column(String, nullable=True)                   # 위치/주소
    is_active = Column(Boolean, default=True)                  # 활성/비활성
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("UserTable", back_populates="site")


class UserTable(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)  # 로그인 아이디
    password = Column(String, nullable=False)                           # 비밀번호(※ 실제 서비스에서는 해싱 필요)
    full_name = Column(String)                                          # 이름
    birth_date = Column(Date)                                           # 생년월일
    gender = Column(String)                                             # 성별
    role = Column(String, nullable=False)                               # worker/manager
    trade_type = Column(String)                                         # 담당 공종 (철근, 거푸집 등)
    phone = Column(String)                                              # 전화번호
    email = Column(String)                                              # 이메일
    disabled = Column(Boolean, default=False)                           # 비활성화 여부

    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)   # 소속 현장

    attendances = relationship("AttendanceTable", back_populates="user")
    site = relationship("SiteTable", back_populates="users")


class AttendanceTable(Base):
    __tablename__ = "attendance"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date = Column(Date, index=True)              # 출근 일자
    check_in_time = Column(DateTime, nullable=True)   # 출근 시간
    check_out_time = Column(DateTime, nullable=True)  # 퇴근 시간
    check_in_status = Column(String, nullable=True)   # 정상 출근 / 지각
    check_out_status = Column(String, nullable=True)  # 정상 퇴근 / 조퇴

    user = relationship("UserTable", back_populates="attendances")


class NoticeTable(Base):
    __tablename__ = "notices"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)     # 공지 제목
    content = Column(Text, nullable=False)     # 공지 내용
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    writer_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    writer = relationship("UserTable")


# ---------- 비상 알림 테이블 ----------
class EmergencyAlertTable(Base):
    __tablename__ = "emergency_alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)          # 어떤 비상 상황인지
    location_text = Column(String, nullable=True)   # 위치 정보(예: "B2 주차장 램프 인근")
    created_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False)    # 처리 여부
    resolved_at = Column(DateTime, nullable=True)   # 처리 완료 시간
    resolved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("UserTable", foreign_keys=[user_id])
    resolved_by = relationship("UserTable", foreign_keys=[resolved_by_id])


# ---------- 하자/문제 신고 테이블 ----------
class IssueReportTable(Base):
    __tablename__ = "issue_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)          # 이슈 제목
    description = Column(Text, nullable=False)      # 상세 내용
    issue_type = Column(String, nullable=True)      # 유형(예: 안전, 품질, 공정, 기타 등)
    status = Column(String, default="등록됨")        # 등록됨 / 처리 중 / 완료
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # ✅ 첨부 이미지 정보
    image_path = Column(String, nullable=True)
    image_original_name = Column(String, nullable=True)

    user = relationship("UserTable")


# ---------- 도면/문서 테이블 ----------
class DrawingTable(Base):
    __tablename__ = "drawings"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)                # 도면 제목
    description = Column(Text, nullable=True)             # 설명
    file_path = Column(String, nullable=False)            # 서버에 저장된 파일 경로
    original_filename = Column(String, nullable=False)    # 업로드 당시 파일 이름
    content_type = Column(String, nullable=True)          # MIME type (pdf, image 등)
    created_at = Column(DateTime, default=datetime.utcnow)
    uploader_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    uploader = relationship("UserTable")


# ---------- 공정(프로세스) 관리 테이블 ----------
class ProcessTaskTable(Base):
    """
    공정 관리:
    - 어느 위치에서(location)
    - 어떤 공정(work_name)이
    - 언제(start_date ~ end_date) 진행되는지 공유하는 테이블
    -> 작업자들이 서로 간섭 없도록 공정/위치 정보를 확인할 수 있음
    """
    __tablename__ = "process_tasks"

    id = Column(Integer, primary_key=True, index=True)
    location = Column(String, nullable=False)        # 위치(예: "1층 3구역 기둥", "B2 램프")
    work_name = Column(String, nullable=False)       # 공정명/작업명(예: "슬래브 철근 배근", "거푸집 해체")
    description = Column(Text, nullable=True)        # 상세 설명(주의사항, 장비, 인원 등)
    start_date = Column(Date, nullable=True)         # 시작 예정일
    end_date = Column(Date, nullable=True)           # 종료 예정일
    status = Column(String, default="계획")          # 계획 / 진행 중 / 완료 등
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    created_by = relationship("UserTable")


# 테이블 생성 (없으면 생성)
Base.metadata.create_all(bind=engine)


# =========================
# Pydantic 모델 (API 입출력용)
# =========================
class Token(BaseModel):
    access_token: str
    token_type: str


# ----- Site Pydantic -----
class SiteBase(BaseModel):
    name: str
    description: Optional[str] = None
    location: Optional[str] = None


class SiteCreate(SiteBase):
    pass


class SiteRead(SiteBase):
    id: int
    is_active: bool
    created_at: datetime


class User(BaseModel):
    id: Optional[int] = None
    username: str
    full_name: Optional[str] = None
    birth_date: Optional[date] = None
    gender: Optional[Gender] = None
    role: Role
    trade_type: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = False
    site_id: int   # 소속 현장 ID


class UserInDB(User):
    password: str


class SignupUser(BaseModel):
    username: str
    password: str
    full_name: str
    birth_date: date
    gender: Gender
    role: Role
    trade_type: str
    phone: str
    email: str

    # 가입 방식 2가지 지원
    site_id: Optional[int] = None            # 기존 현장에 가입
    site_name: Optional[str] = None          # 새 현장 생성용 (관리자만)
    site_description: Optional[str] = None
    site_location: Optional[str] = None


class UpdateUser(BaseModel):
    full_name: Optional[str] = None
    birth_date: Optional[date] = None
    gender: Optional[Gender] = None
    trade_type: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None  # 비밀번호 변경(선택)


class AttendanceRecord(BaseModel):
    id: Optional[int] = None
    date: date
    username: str
    full_name: Optional[str] = None
    role: Role
    check_in_time: Optional[datetime] = None
    check_out_time: Optional[datetime] = None
    check_in_status: Optional[str] = None
    check_out_status: Optional[str] = None


class NoticeBase(BaseModel):
    title: str
    content: str


class NoticeCreate(NoticeBase):
    pass


class NoticeUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None


class NoticeRead(NoticeBase):
    id: int
    created_at: datetime
    updated_at: datetime
    writer_username: str
    writer_full_name: Optional[str] = None


# ---------- 비상 알림 Pydantic ----------
class EmergencyAlertBase(BaseModel):
    message: str
    location_text: Optional[str] = None


class EmergencyAlertCreate(EmergencyAlertBase):
    pass


class EmergencyAlertRead(EmergencyAlertBase):
    id: int
    user_id: int
    username: str
    full_name: Optional[str] = None
    created_at: datetime
    is_resolved: bool
    resolved_at: Optional[datetime] = None
    resolved_by_username: Optional[str] = None
    resolved_by_full_name: Optional[str] = None


# ---------- 하자/문제 신고 Pydantic ----------
class IssueBase(BaseModel):
    title: str
    description: str
    issue_type: Optional[str] = None  # 예: "안전", "품질", "공정", "기타"


class IssueCreate(IssueBase):
    pass


class IssueUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    issue_type: Optional[str] = None
    status: Optional[str] = None  # "등록됨", "처리 중", "완료"


class IssueRead(IssueBase):
    id: int
    username: str
    full_name: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    image_url: Optional[str] = None

# ---------- 도면 Pydantic ----------
class DrawingBase(BaseModel):
    title: str
    description: Optional[str] = None


class DrawingRead(DrawingBase):
    id: int
    original_filename: str
    content_type: Optional[str] = None
    created_at: datetime
    uploader_username: str
    uploader_full_name: Optional[str] = None


# ---------- 공정 관리 Pydantic ----------
class ProcessBase(BaseModel):
    location: str
    work_name: str
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = "계획"  # 기본값: 계획


class ProcessCreate(ProcessBase):
    pass


class ProcessUpdate(BaseModel):
    location: Optional[str] = None
    work_name: Optional[str] = None
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = None


class ProcessRead(ProcessBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by_username: str
    created_by_full_name: Optional[str] = None


# =========================
# 설정 값, 앱, OAuth2
# =========================
SECRET_KEY = "YOUR_SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

WORK_START_TIME = time(7, 50)   # 07:50 이후 출근 → 지각
WORK_END_TIME = time(16, 30)    # 16:30 이전 퇴근 → 조퇴

app = FastAPI(
    title="건설 현장 출석 · 공지 · 도면 · 공정 관리 API (다중 현장 커뮤니티)",
    openapi_tags=[
        {
            "name": "공용 기능",
            "description": "회원가입, 로그인, 내 정보 및 출석 관리 등 모든 사용자가 공통으로 사용하는 기능",
        },
        {
            "name": "작업자 기능",
            "description": "현장 작업자가 사용하는 기능 (공지/도면 조회, 비상 알림, 하자 신고, 공정 관리 등)",
        },
        {
            "name": "관리자 기능",
            "description": "관리자가 사용하는 관리 기능 (현장/사용자/출석/공지/도면/신고 관리 등)",
        },
    ],
)
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 테스트 단계에서는 모두 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# CORS 설정 (프론트엔드에서 호출 가능하게)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 개발용: 전체 허용. 나중에 필요하면 도메인 제한.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# DB 세션 의존성
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# 유틸 함수
# =========================
def site_row_to_schema(row: SiteTable) -> SiteRead:
    return SiteRead(
        id=row.id,
        name=row.name,
        description=row.description,
        location=row.location,
        is_active=row.is_active,
        created_at=row.created_at,
    )


def get_user_by_username(db: Session, username: str) -> Optional[UserInDB]:
    row = db.query(UserTable).filter(UserTable.username == username).first()
    if not row:
        return None

    gender = Gender(row.gender) if row.gender else None
    role = Role(row.role)

    return UserInDB(
        id=row.id,
        username=row.username,
        full_name=row.full_name,
        birth_date=row.birth_date,
        gender=gender,
        role=role,
        trade_type=row.trade_type,
        phone=row.phone,
        email=row.email,
        disabled=row.disabled,
        site_id=row.site_id,
        password=row.password,
    )


def authenticate_user(db: Session, username: str, password: str) -> Optional[UserInDB]:
    """
    아이디/비밀번호로 사용자 인증
    """
    user = get_user_by_username(db, username)
    if not user:
        return None
    if password != user.password:
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    JWT 액세스 토큰 생성
    - data: 토큰에 포함할 데이터 (예: {"sub": username, "role": "worker"})
    - expires_delta: 만료 시간 (기본 60분)
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_today_attendance(db: Session, user_id: int) -> AttendanceTable:
    """
    특정 사용자의 오늘 출석 레코드를 가져오거나, 없으면 새로 생성
    """
    today = date.today()
    row = (
        db.query(AttendanceTable)
        .filter(AttendanceTable.user_id == user_id, AttendanceTable.date == today)
        .first()
    )
    if row:
        return row

    row = AttendanceTable(user_id=user_id, date=today)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def attendance_row_to_schema(row: AttendanceTable) -> AttendanceRecord:
    return AttendanceRecord(
        id=row.id,
        date=row.date,
        username=row.user.username,
        full_name=row.user.full_name,
        role=Role(row.user.role),
        check_in_time=row.check_in_time,
        check_out_time=row.check_out_time,
        check_in_status=row.check_in_status,
        check_out_status=row.check_out_status,
    )


def notice_row_to_schema(row: NoticeTable) -> NoticeRead:
    return NoticeRead(
        id=row.id,
        title=row.title,
        content=row.content,
        created_at=row.created_at,
        updated_at=row.updated_at,
        writer_username=row.writer.username,
        writer_full_name=row.writer.full_name,
    )


def user_row_to_schema(row: UserTable) -> User:
    gender = Gender(row.gender) if row.gender else None
    role = Role(row.role)
    return User(
        id=row.id,
        username=row.username,
        full_name=row.full_name,
        birth_date=row.birth_date,
        gender=gender,
        role=role,
        trade_type=row.trade_type,
        phone=row.phone,
        email=row.email,
        disabled=row.disabled,
        site_id=row.site_id,
    )


def emergency_row_to_schema(row: EmergencyAlertTable) -> EmergencyAlertRead:
    return EmergencyAlertRead(
        id=row.id,
        message=row.message,
        location_text=row.location_text,
        user_id=row.user_id,
        username=row.user.username,
        full_name=row.user.full_name,
        created_at=row.created_at,
        is_resolved=row.is_resolved,
        resolved_at=row.resolved_at,
        resolved_by_username=row.resolved_by.username if row.resolved_by else None,
        resolved_by_full_name=row.resolved_by.full_name if row.resolved_by else None,
    )


def issue_row_to_schema(row: IssueReportTable) -> IssueRead:
    image_url = None
    if row.image_path:
        image_url = f"/issues/{row.id}/file"

    # row.user 가 None 일 수 있기 때문에 안전하게 처리
    username = row.user.username if row.user else "알 수 없음"
    full_name = row.user.full_name if row.user else None

    return IssueRead(
        id=row.id,
        title=row.title,
        description=row.description,
        issue_type=row.issue_type,
        username=username,
        full_name=full_name,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        image_url=image_url,
    )



def drawing_row_to_schema(row: DrawingTable) -> DrawingRead:
    return DrawingRead(
        id=row.id,
        title=row.title,
        description=row.description,
        original_filename=row.original_filename,
        content_type=row.content_type,
        created_at=row.created_at,
        uploader_username=row.uploader.username,
        uploader_full_name=row.uploader.full_name,
    )


def process_row_to_schema(row: ProcessTaskTable) -> ProcessRead:
    return ProcessRead(
        id=row.id,
        location=row.location,
        work_name=row.work_name,
        description=row.description,
        start_date=row.start_date,
        end_date=row.end_date,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        created_by_username=row.created_by.username,
        created_by_full_name=row.created_by.full_name,
    )


# =========================
# 토큰 → 현재 사용자
# =========================
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserInDB:
    """
    헤더의 Bearer 토큰으로부터 현재 로그인한 사용자 정보 가져오기
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="토큰이 유효하지 않습니다. 다시 로그인 해주세요.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    if user.disabled:
        raise HTTPException(status_code=400, detail="비활성화된 사용자입니다.")
    return user


async def get_current_active_manager(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """
    현재 사용자가 관리자(manager)인지 확인
    """
    if current_user.role != Role.manager:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="관리자(manager) 권한이 필요합니다.",
        )
    return current_user


# =========================
# 현장(Site) 관리 (관리자 기능)
# =========================
@app.post("/sites", response_model=SiteRead, tags=["관리자 기능"])
async def create_site(
    site: SiteCreate,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 현장 생성 (관리자 전용)

    - name: 현장 이름 (예: "노원 ○○아파트 신축공사")
    - description: 설명
    - location: 위치/주소
    """
    if db.query(SiteTable).filter(SiteTable.name == site.name).first():
        raise HTTPException(status_code=400, detail="이미 존재하는 현장 이름입니다.")

    row = SiteTable(
        name=site.name,
        description=site.description,
        location=site.location,
        is_active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return site_row_to_schema(row)


@app.get("/sites", response_model=List[SiteRead], tags=["관리자 기능"])
async def list_sites(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 전체 현장 목록 조회 (관리자 전용)
    """
    rows = db.query(SiteTable).order_by(SiteTable.created_at.desc()).all()
    return [site_row_to_schema(r) for r in rows]


@app.get("/sites/{site_id}", response_model=SiteRead, tags=["관리자 기능"])
async def get_site(
    site_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 현장 상세 조회 (관리자 전용)
    """
    row = db.query(SiteTable).filter(SiteTable.id == site_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="현장을 찾을 수 없습니다.")
    return site_row_to_schema(row)


# =========================
# 공용 기능: 회원가입 / 로그인 / 내 정보 / 출석
# =========================
@app.post("/signup", response_model=User, tags=["공용 기능"])
async def signup(user: SignupUser, db: Session = Depends(get_db)):
    """
    ▶ 회원가입 (근로자/관리자 공용)

    회원가입 방식 2가지:
    1) 이미 존재하는 현장에 가입
       - site_id 를 함께 보냄

    2) 관리자(role=manager)가 새 현장을 만들면서 가입
       - site_id 는 비우고
       - site_name / site_description / site_location 을 채워서 보냄
    """

    # 아이디 중복 체크
    if db.query(UserTable).filter(UserTable.username == user.username).first():
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")

    site_id: Optional[int] = None

    # (1) 기존 현장에 가입 (site_id 제공)
    if user.site_id is not None:
        site = (
            db.query(SiteTable)
            .filter(SiteTable.id == user.site_id, SiteTable.is_active == True)
            .first()
        )
        if not site:
            raise HTTPException(status_code=400, detail="유효한 현장(site_id)이 아닙니다.")
        site_id = site.id

    else:
        # (2) 새 현장 생성 + 가입 (관리자만 가능)
        if user.role == Role.manager and user.site_name:
            if db.query(SiteTable).filter(SiteTable.name == user.site_name).first():
                raise HTTPException(status_code=400, detail="이미 존재하는 현장 이름입니다.")

            new_site = SiteTable(
                name=user.site_name,
                description=user.site_description,
                location=user.site_location,
                is_active=True,
            )
            db.add(new_site)
            db.commit()
            db.refresh(new_site)
            site_id = new_site.id
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "site_id가 없으면, 관리자(role=manager)인 경우 "
                    "site_name을 함께 보내 새 현장을 생성해야 합니다."
                ),
            )

    # 사용자 생성
    row = UserTable(
        username=user.username,
        password=user.password,
        full_name=user.full_name,
        birth_date=user.birth_date,
        gender=user.gender.value,
        role=user.role.value,
        trade_type=user.trade_type,
        phone=user.phone,
        email=user.email,
        disabled=False,
        site_id=site_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return user_row_to_schema(row)


@app.post("/login", response_model=Token, tags=["공용 기능"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    ▶ 로그인 (근로자/관리자 공용)

    - username / password로 로그인
    - 응답으로 발급되는 access_token을 Swagger 상단 [Authorize]에 입력 후 사용
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        {"sub": user.username, "role": user.role.value}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=User, tags=["공용 기능"])
async def read_me(current_user: UserInDB = Depends(get_current_user)):
    """
    ▶ 현재 로그인한 내 정보 조회
    """
    return current_user


@app.put("/me", response_model=User, tags=["공용 기능"])
async def update_me(
    update: UpdateUser,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 내 정보 수정

    - 수정 가능: 이름, 생년월일, 성별, 공종, 전화번호, 이메일, 비밀번호
    - 수정 불가: username(아이디), role(역할), site_id(현장)
    """
    row = db.query(UserTable).filter(UserTable.id == current_user.id).first()
    if not row:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if update.full_name is not None:
        row.full_name = update.full_name
    if update.birth_date is not None:
        row.birth_date = update.birth_date
    if update.gender is not None:
        row.gender = update.gender.value
    if update.trade_type is not None:
        row.trade_type = update.trade_type
    if update.phone is not None:
        row.phone = update.phone
    if update.email is not None:
        row.email = update.email
    if update.password is not None and update.password != "":
        row.password = update.password

    db.add(row)
    db.commit()
    db.refresh(row)

    updated = get_user_by_username(db, row.username)
    return updated


@app.post("/attendance/check-in", response_model=AttendanceRecord, tags=["공용 기능"])
async def check_in(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 출근 처리 (작업자/관리자 공통 사용)

    - 하루에 한 번만 가능
    - 기준 시간(WORK_START_TIME=07:50) 이전: "정상 출근"
    - 기준 시간 이후: "지각"
    """
    now = datetime.now()
    row = get_today_attendance(db, current_user.id)

    if row.check_in_time is not None:
        raise HTTPException(status_code=400, detail="이미 출근 처리되었습니다.")

    if now.time() <= WORK_START_TIME:
        row.check_in_status = "정상 출근"
    else:
        row.check_in_status = "지각"

    row.check_in_time = now
    db.add(row)
    db.commit()
    db.refresh(row)
    return attendance_row_to_schema(row)


@app.post("/attendance/check-out", response_model=AttendanceRecord, tags=["공용 기능"])
async def check_out(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 퇴근 처리 (작업자/관리자 공통 사용)

    - 출근 기록이 있어야 퇴근 가능
    - 기준 시간(WORK_END_TIME=16:30) 이후: "정상 퇴근"
    - 기준 시간 이전: "조퇴"
    """
    now = datetime.now()
    row = get_today_attendance(db, current_user.id)

    if row.check_in_time is None:
        raise HTTPException(status_code=400, detail="먼저 출근 처리를 해야 합니다.")
    if row.check_out_time is not None:
        raise HTTPException(status_code=400, detail="이미 퇴근 처리되었습니다.")

    if now.time() >= WORK_END_TIME:
        row.check_out_status = "정상 퇴근"
    else:
        row.check_out_status = "조퇴"

    row.check_out_time = now
    db.add(row)
    db.commit()
    db.refresh(row)
    return attendance_row_to_schema(row)


@app.get(
    "/attendance/me",
    response_model=List[AttendanceRecord],
    tags=["공용 기능"],
)
async def my_attendance(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 내 출석 기록 전체 조회

    - 최근 날짜 순으로 정렬
    """
    rows = (
        db.query(AttendanceTable)
        .join(UserTable)
        .filter(UserTable.id == current_user.id)
        .order_by(AttendanceTable.date.desc())
        .all()
    )
    return [attendance_row_to_schema(r) for r in rows]


# =========================
# 관리자 기능: 사용자 / 출석 관리 (현장 기준)
# =========================
@app.get(
    "/manager/users",
    response_model=List[User],
    tags=["관리자 기능"],
)
async def manager_list_users(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 내 현장 전체 사용자 목록 조회 (관리자 전용)
    """
    rows = (
        db.query(UserTable)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(UserTable.username)
        .all()
    )
    return [user_row_to_schema(r) for r in rows]


@app.get(
    "/manager/users/{username}",
    response_model=User,
    tags=["관리자 기능"],
)
async def manager_get_user(
    username: str,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 사용자 상세 정보 조회 (관리자 전용, 같은 현장만)
    """
    row = (
        db.query(UserTable)
        .filter(
            UserTable.username == username,
            UserTable.site_id == current_user.site_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    return user_row_to_schema(row)


@app.get(
    "/manager/attendance/all",
    response_model=List[AttendanceRecord],
    tags=["관리자 기능"],
)
async def manager_all_attendance(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 내 현장 전체 인원 출석 기록 조회 (관리자 전용)
    """
    rows = (
        db.query(AttendanceTable)
        .join(UserTable)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(AttendanceTable.date.desc(), UserTable.username)
        .all()
    )
    return [attendance_row_to_schema(r) for r in rows]


@app.get(
    "/manager/attendance/user/{username}",
    response_model=List[AttendanceRecord],
    tags=["관리자 기능"],
)
async def manager_user_attendance(
    username: str,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 사용자 출석 기록 조회 (관리자 전용, 같은 현장)
    """
    rows = (
        db.query(AttendanceTable)
        .join(UserTable)
        .filter(
            UserTable.username == username,
            UserTable.site_id == current_user.site_id,
        )
        .order_by(AttendanceTable.date.desc())
        .all()
    )
    return [attendance_row_to_schema(r) for r in rows]


@app.get(
    "/manager/attendance/today",
    response_model=List[AttendanceRecord],
    tags=["관리자 기능"],
)
async def manager_today_attendance(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 내 현장 오늘자 출석 현황 조회 (관리자 전용)
    """
    today = date.today()
    rows = (
        db.query(AttendanceTable)
        .join(UserTable)
        .filter(
            AttendanceTable.date == today,
            UserTable.site_id == current_user.site_id,
        )
        .order_by(UserTable.username)
        .all()
    )
    return [attendance_row_to_schema(r) for r in rows]


@app.get(
    "/manager/attendance/export-csv",
    tags=["관리자 기능"],
)
async def export_attendance_csv(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
    username: Optional[str] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
):
    """
    ▶ 출석 기록 CSV 다운로드 (관리자 전용, 내 현장만)

    - username: 특정 사용자만 필터링 (옵션)
    - start_date, end_date: 기간 필터 (옵션)
    """
    query = (
        db.query(AttendanceTable)
        .join(UserTable)
        .filter(UserTable.site_id == current_user.site_id)
    )

    if username is not None:
        query = query.filter(UserTable.username == username)
    if start_date is not None:
        query = query.filter(AttendanceTable.date >= start_date)
    if end_date is not None:
        query = query.filter(AttendanceTable.date <= end_date)

    rows = query.order_by(AttendanceTable.date, UserTable.username).all()

    # 🔹 줄바꿈 문제 방지를 위해 newline="" 사용
    output = io.StringIO(newline="")
    writer = csv.writer(output)

    # 🔹 줄바꿈 문제 방지를 위해 newline="" 사용
    output = io.StringIO(newline="")
    writer = csv.writer(output)

    # ✅ 한글 컬럼명으로 변경
    writer.writerow(
        [
            "출석ID",
            "아이디",
            "이름",
            "역할",
            "날짜",
            "출근시간",
            "출근상태",
            "퇴근시간",
            "퇴근상태",
        ]
    )

    for r in rows:
        # 역할 한글화
        if r.user.role == "manager":
            role_kr = "관리자"
        else:
            role_kr = "근로자"

        # 날짜/시간 보기 좋게 포맷
        date_str = r.date.strftime("%Y-%m-%d") if r.date else ""
        time_fmt = "%Y-%m-%d %H:%M"

        check_in_str = (
            r.check_in_time.strftime(time_fmt) if r.check_in_time else ""
        )
        check_out_str = (
            r.check_out_time.strftime(time_fmt) if r.check_out_time else ""
        )

        writer.writerow(
            [
                r.id,
                r.user.username,
                r.user.full_name or "",
                role_kr,
                date_str,
                check_in_str,
                r.check_in_status or "",
                check_out_str,
                r.check_out_status or "",
            ]
        )

    # 🔹 UTF-8 BOM(utf-8-sig)으로 인코딩해서 한글 깨짐 방지
    output.seek(0)
    csv_bytes = output.getvalue().encode("utf-8-sig")

    response = StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv; charset=utf-8",
    )
    # 🔹 파일 이름도 UTF-8 규격으로 지정
    response.headers["Content-Disposition"] = "attachment; filename*=UTF-8''attendance.csv"
    return response


# =========================
# 작업자 기능: 공지사항 조회
# =========================
@app.get(
    "/notices",
    response_model=List[NoticeRead],
    tags=["작업자 기능"],
)
async def list_notices(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 공지사항 목록 조회 (최신 순)

    - 내 현장(manager)이 작성한 공지사항만 작업자/관리자 모두 확인
    """
    rows = (
        db.query(NoticeTable)
        .join(UserTable, NoticeTable.writer_id == UserTable.id)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(NoticeTable.created_at.desc())
        .all()
    )
    return [notice_row_to_schema(r) for r in rows]


@app.get(
    "/notices/{notice_id}",
    response_model=NoticeRead,
    tags=["작업자 기능"],
)
async def get_notice(
    notice_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 공지사항 상세 조회
    """
    row = (
        db.query(NoticeTable)
        .join(UserTable, NoticeTable.writer_id == UserTable.id)
        .filter(NoticeTable.id == notice_id)
        .first()
    )
    if not row or row.writer.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")
    return notice_row_to_schema(row)


# =========================
# 관리자 기능: 공지사항 작성/수정/삭제
# =========================
@app.post(
    "/manager/notices",
    response_model=NoticeRead,
    tags=["관리자 기능"],
)
async def create_notice(
    notice: NoticeCreate,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 공지사항 등록 (관리자 전용, 내 현장 공지)
    """
    row = NoticeTable(
        title=notice.title,
        content=notice.content,
        writer_id=current_user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return notice_row_to_schema(row)


@app.put(
    "/manager/notices/{notice_id}",
    response_model=NoticeRead,
    tags=["관리자 기능"],
)
async def update_notice(
    notice_id: int,
    notice: NoticeUpdate,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 공지사항 수정 (관리자 전용, 같은 현장 공지만)
    """
    row = db.query(NoticeTable).filter(NoticeTable.id == notice_id).first()
    if not row or row.writer.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")

    if notice.title is not None:
        row.title = notice.title
    if notice.content is not None:
        row.content = notice.content

    db.add(row)
    db.commit()
    db.refresh(row)
    return notice_row_to_schema(row)


@app.delete(
    "/manager/notices/{notice_id}",
    tags=["관리자 기능"],
)
async def delete_notice(
    notice_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 공지사항 삭제 (관리자 전용, 같은 현장 공지만)
    """
    row = db.query(NoticeTable).filter(NoticeTable.id == notice_id).first()
    if not row or row.writer.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공지사항을 찾을 수 없습니다.")

    db.delete(row)
    db.commit()
    return {"detail": "공지사항이 삭제되었습니다."}


# =========================
# 비상 알림 (작업자 등록 / 관리자 관리)
# =========================
@app.post(
    "/alerts/emergency",
    response_model=EmergencyAlertRead,
    tags=["작업자 기능"],
)
async def create_emergency_alert(
    alert: EmergencyAlertCreate,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 비상 알림 등록 (작업자/관리자 공용)

    - 예: 추락, 협착, 화재 위험 등 긴급 상황을 빠르게 공유
    - message: 어떤 상황인지
    - location_text: 위치 설명 (층/구역 등)
    """
    row = EmergencyAlertTable(
        user_id=current_user.id,
        message=alert.message,
        location_text=alert.location_text,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return emergency_row_to_schema(row)


@app.get(
    "/alerts/emergency/me",
    response_model=List[EmergencyAlertRead],
    tags=["작업자 기능"],
)
async def my_emergency_alerts(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 내가 등록한 비상 알림 목록 조회
    """
    rows = (
        db.query(EmergencyAlertTable)
        .join(UserTable, EmergencyAlertTable.user_id == UserTable.id)
        .filter(EmergencyAlertTable.user_id == current_user.id)
        .order_by(EmergencyAlertTable.created_at.desc())
        .all()
    )
    return [emergency_row_to_schema(r) for r in rows]


@app.get(
    "/manager/alerts/emergency",
    response_model=List[EmergencyAlertRead],
    tags=["관리자 기능"],
)
async def manager_list_emergency_alerts(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
    is_resolved: Optional[bool] = None,
):
    """
    ▶ 비상 알림 전체 조회 (관리자 전용, 내 현장만)

    - is_resolved: True/False 로 처리 여부 필터링 가능
    """
    query = (
        db.query(EmergencyAlertTable)
        .join(UserTable, EmergencyAlertTable.user_id == UserTable.id)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(EmergencyAlertTable.created_at.desc())
    )

    if is_resolved is not None:
        query = query.filter(EmergencyAlertTable.is_resolved == is_resolved)

    rows = query.all()
    return [emergency_row_to_schema(r) for r in rows]


@app.put(
    "/manager/alerts/emergency/{alert_id}/resolve",
    response_model=EmergencyAlertRead,
    tags=["관리자 기능"],
)
async def resolve_emergency_alert(
    alert_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 비상 알림 처리 완료 표시 (관리자 전용, 같은 현장)
    """
    row = db.query(EmergencyAlertTable).filter(EmergencyAlertTable.id == alert_id).first()
    if not row or row.user.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="비상 알림을 찾을 수 없습니다.")

    row.is_resolved = True
    row.resolved_at = datetime.utcnow()
    row.resolved_by_id = current_user.id

    db.add(row)
    db.commit()
    db.refresh(row)
    return emergency_row_to_schema(row)


# =========================
# 하자/문제 신고 (작업자 등록 / 관리자 관리)
# =========================
@app.post(
    "/issues",
    response_model=IssueRead,
    tags=["작업자 기능"],
)

async def create_issue(
    title: str = Form(...),
    description: str = Form(...),
    issue_type: Optional[str] = Form(None),
    photo: Optional[UploadFile] = File(None),
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 하자/문제 신고 등록 (작업자/관리자 공용)
    - title: 문제 제목
    - description: 상세 내용
    - issue_type: 안전/품질/공정/기타 등 분류
    - photo: 현장 사진 (선택)
    """
    image_path = None
    image_original_name = None

    if photo is not None:
        _, ext = os.path.splitext(photo.filename)
        unique_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(ISSUE_UPLOAD_DIR, unique_name)

        file_bytes = await photo.read()
        with open(save_path, "wb") as f:
            f.write(file_bytes)

        image_path = save_path
        image_original_name = photo.filename

    row = IssueReportTable(
        user_id=current_user.id,
        title=title,
        description=description,
        issue_type=issue_type,
        status="등록됨",
        image_path=image_path,
        image_original_name=image_original_name,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return issue_row_to_schema(row)

@app.get(
    "/issues/{issue_id}/file",
    tags=["작업자 기능"],
)
async def get_issue_file(
    issue_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 하자 신고에 첨부된 사진 파일 다운로드
    """
    row = db.query(IssueReportTable).filter(IssueReportTable.id == issue_id).first()
    if not row or row.user.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="하자/문제 신고를 찾을 수 없습니다.")

    # 파일이 없으면 404 말고 204(내용 없음) 반환!
    if not row.image_path or not os.path.exists(row.image_path):
        return Response(status_code=204)

    return FileResponse(
        row.image_path,
        filename=row.image_original_name or "issue_file",
    )


@app.get(
    "/issues/me",
    response_model=List[IssueRead],
    tags=["작업자 기능"],
)
async def my_issues(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 내가 등록한 하자/문제 신고 목록 조회
    """
    rows = (
        db.query(IssueReportTable)
        .join(UserTable, IssueReportTable.user_id == UserTable.id)
        .filter(IssueReportTable.user_id == current_user.id)
        .order_by(IssueReportTable.created_at.desc())
        .all()
    )
    return [issue_row_to_schema(r) for r in rows]


@app.get(
    "/manager/issues",
    response_model=List[IssueRead],
    tags=["관리자 기능"],
)
async def manager_list_issues(
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
    status: Optional[str] = None,
):
    """
    ▶ 하자/문제 신고 전체 목록 조회 (관리자 전용, 내 현장만)

    - status: "등록됨", "처리 중", "완료" 등으로 필터 가능
    """
    query = (
        db.query(IssueReportTable)
        .join(UserTable, IssueReportTable.user_id == UserTable.id)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(IssueReportTable.created_at.desc())
    )

    if status is not None and status != "":
        query = query.filter(IssueReportTable.status == status)

    rows = query.all()
    return [issue_row_to_schema(r) for r in rows]


@app.get(
    "/manager/issues/{issue_id}",
    response_model=IssueRead,
    tags=["관리자 기능"],
)
async def manager_get_issue(
    issue_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 하자/문제 신고 상세 조회 (관리자 전용, 같은 현장)
    """
    row = (
        db.query(IssueReportTable)
        .join(UserTable, IssueReportTable.user_id == UserTable.id)
        .filter(IssueReportTable.id == issue_id)
        .first()
    )
    if not row or row.user.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="하자/문제 신고를 찾을 수 없습니다.")
    return issue_row_to_schema(row)


@app.put(
    "/manager/issues/{issue_id}",
    response_model=IssueRead,
    tags=["관리자 기능"],
)
async def manager_update_issue(
    issue_id: int,
    issue_update: IssueUpdate,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 하자/문제 신고 내용 및 상태 수정 (관리자 전용, 같은 현장)
    """
    row = db.query(IssueReportTable).filter(IssueReportTable.id == issue_id).first()
    if not row or row.user.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="하자/문제 신고를 찾을 수 없습니다.")

    if issue_update.title is not None:
        row.title = issue_update.title
    if issue_update.description is not None:
        row.description = issue_update.description
    if issue_update.issue_type is not None:
        row.issue_type = issue_update.issue_type
    if issue_update.status is not None and issue_update.status != "":
        row.status = issue_update.status

    db.add(row)
    db.commit()
    db.refresh(row)
    return issue_row_to_schema(row)


@app.delete(
    "/manager/issues/{issue_id}",
    tags=["관리자 기능"],
)
async def manager_delete_issue(
    issue_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 하자/문제 신고 삭제 (관리자 전용, 같은 현장)
    """
    row = db.query(IssueReportTable).filter(IssueReportTable.id == issue_id).first()
    if not row or row.user.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="하자/문제 신고를 찾을 수 없습니다.")

    db.delete(row)
    db.commit()
    return {"detail": "하자/문제 신고가 삭제되었습니다."}


# =========================
# 도면 업로드 / 조회 / 다운로드
# =========================
@app.post(
    "/manager/drawings",
    response_model=DrawingRead,
    tags=["관리자 기능"],
)
async def upload_drawing(
    title: str = Form(...),
    description: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 도면 파일 업로드 (관리자 전용, 내 현장)

    - PDF, 이미지 등 도면 파일을 서버에 업로드하고
      작업자들이 /drawings API로 조회하여 볼 수 있음
    """
    _, ext = os.path.splitext(file.filename)
    unique_name = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(UPLOAD_DIR, unique_name)

    file_bytes = await file.read()
    with open(save_path, "wb") as f:
        f.write(file_bytes)

    row = DrawingTable(
        title=title,
        description=description,
        file_path=save_path,
        original_filename=file.filename,
        content_type=file.content_type,
        uploader_id=current_user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return drawing_row_to_schema(row)

@app.get("/drawings/file/{file_id}")
async def download_drawing(file_id: int, db: Session = Depends(get_db), current_user: UserInDB = Depends(get_current_user)):
    file = db.query(DrawingTable).filter(DrawingTable.id == file_id).first()

    if not file or file.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다.")

    if not os.path.exists(file.file_path):
        raise HTTPException(status_code=404, detail="저장된 파일이 존재하지 않습니다.")

    return FileResponse(
        file.file_path,
        filename=file.original_name,
        media_type="application/octet-stream"
    )

@app.get(
    "/drawings",
    response_model=List[DrawingRead],
    tags=["작업자 기능"],
)
async def list_drawings(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 도면 목록 조회 (작업자/관리자 공용)

    - 내 현장의 관리자들이 업로드한 도면 리스트 확인
    """
    rows = (
        db.query(DrawingTable)
        .join(UserTable, DrawingTable.uploader_id == UserTable.id)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(DrawingTable.created_at.desc())
        .all()
    )
    return [drawing_row_to_schema(r) for r in rows]


@app.get(
    "/drawings/{drawing_id}",
    response_model=DrawingRead,
    tags=["작업자 기능"],
)
async def get_drawing(
    drawing_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 도면 메타데이터 조회 (제목, 설명, 업로더 정보 등)
    """
    row = (
        db.query(DrawingTable)
        .join(UserTable, DrawingTable.uploader_id == UserTable.id)
        .filter(DrawingTable.id == drawing_id)
        .first()
    )
    if not row or row.uploader.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="도면을 찾을 수 없습니다.")
    return drawing_row_to_schema(row)


@app.get(
    "/drawings/{drawing_id}/file",
    tags=["작업자 기능"],
)
async def download_drawing_file(
    drawing_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 도면 파일 다운로드 (작업자/관리자 공용)

    - 브라우저에서 바로 열리거나, 파일로 저장됨
    """
    row = db.query(DrawingTable).filter(DrawingTable.id == drawing_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="도면을 찾을 수 없습니다.")
    if row.uploader.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="도면을 찾을 수 없습니다.")

    if not os.path.exists(row.file_path):
        raise HTTPException(status_code=500, detail="서버에 도면 파일이 존재하지 않습니다.")

    return FileResponse(
        row.file_path,
        media_type=row.content_type or "application/octet-stream",
        filename=row.original_filename,
    )


@app.delete(
    "/manager/drawings/{drawing_id}",
    tags=["관리자 기능"],
)
async def delete_drawing(
    drawing_id: int,
    current_user: UserInDB = Depends(get_current_active_manager),
    db: Session = Depends(get_db),
):
    """
    ▶ 도면 삭제 (파일 + DB 레코드, 관리자 전용, 같은 현장)
    """
    row = db.query(DrawingTable).filter(DrawingTable.id == drawing_id).first()
    if not row or row.uploader.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="도면을 찾을 수 없습니다.")

    if os.path.exists(row.file_path):
        try:
            os.remove(row.file_path)
        except Exception:
            pass

    db.delete(row)
    db.commit()
    return {"detail": "도면이 삭제되었습니다."}


# =========================
# 공정 관리 (작업자 등록/수정/삭제, 모두 조회)
# =========================
@app.post(
    "/processes",
    response_model=ProcessRead,
    tags=["작업자 기능"],
)
async def create_process(
    process: ProcessCreate,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 공정 등록 (작업자/관리자 공용, 작업자 중심)

    - location: 어느 위치에서 (예: "2층 5구역 슬래브")
    - work_name: 어떤 공정인지 (예: "슬래브 타설", "철근 배근")
    - start_date / end_date: 예정 기간 (옵션)
    - status: 계획 / 진행 중 / 완료 등 상태 텍스트
    """
    row = ProcessTaskTable(
        location=process.location,
        work_name=process.work_name,
        description=process.description,
        start_date=process.start_date,
        end_date=process.end_date,
        status=process.status or "계획",
        created_by_id=current_user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return process_row_to_schema(row)


@app.get(
    "/processes",
    response_model=List[ProcessRead],
    tags=["작업자 기능"],
)
async def list_processes(
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
    location: Optional[str] = None,
    target_date: Optional[date] = None,
):
    """
    ▶ 공정 목록 조회 (작업자/관리자 공용, 내 현장 기준)

    - location: 특정 위치 검색 (부분 문자열 포함 검색)
      예) "2층", "B2 램프" 등
    - target_date: 해당 날짜에 진행되는 공정만 필터
      (start_date <= target_date <= end_date 조건)
    """
    query = (
        db.query(ProcessTaskTable)
        .join(UserTable, ProcessTaskTable.created_by_id == UserTable.id)
        .filter(UserTable.site_id == current_user.site_id)
        .order_by(ProcessTaskTable.start_date, ProcessTaskTable.location)
    )

    if location:
        query = query.filter(ProcessTaskTable.location.contains(location))
    if target_date:
        query = query.filter(
            ProcessTaskTable.start_date <= target_date,
            ProcessTaskTable.end_date >= target_date,
        )

    rows = query.all()
    return [process_row_to_schema(r) for r in rows]


@app.get(
    "/processes/{process_id}",
    response_model=ProcessRead,
    tags=["작업자 기능"],
)
async def get_process(
    process_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 특정 공정 상세 정보 조회
    """
    row = (
        db.query(ProcessTaskTable)
        .join(UserTable, ProcessTaskTable.created_by_id == UserTable.id)
        .filter(ProcessTaskTable.id == process_id)
        .first()
    )
    if not row or row.created_by.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공정을 찾을 수 없습니다.")
    return process_row_to_schema(row)


@app.put(
    "/processes/{process_id}",
    response_model=ProcessRead,
    tags=["작업자 기능"],
)
async def update_process(
    process_id: int,
    process_update: ProcessUpdate,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 공정 수정 (작업자/관리자 공용)

    - 작성자 본인 또는 같은 현장의 관리자만 수정 가능
    """
    row = db.query(ProcessTaskTable).filter(ProcessTaskTable.id == process_id).first()
    if not row or row.created_by.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공정을 찾을 수 없습니다.")

    if current_user.role != Role.manager and row.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")

    if process_update.location is not None:
        row.location = process_update.location
    if process_update.work_name is not None:
        row.work_name = process_update.work_name
    if process_update.description is not None:
        row.description = process_update.description
    if process_update.start_date is not None:
        row.start_date = process_update.start_date
    if process_update.end_date is not None:
        row.end_date = process_update.end_date
    if process_update.status is not None:
        row.status = process_update.status

    db.add(row)
    db.commit()
    db.refresh(row)
    return process_row_to_schema(row)


@app.delete(
    "/processes/{process_id}",
    tags=["작업자 기능"],
)
async def delete_process(
    process_id: int,
    current_user: UserInDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ▶ 공정 삭제 (작업자/관리자 공용)

    - 작성자 본인 또는 같은 현장의 관리자만 삭제 가능
    """
    row = db.query(ProcessTaskTable).filter(ProcessTaskTable.id == process_id).first()
    if not row or row.created_by.site_id != current_user.site_id:
        raise HTTPException(status_code=404, detail="공정을 찾을 수 없습니다.")

    if current_user.role != Role.manager and row.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")

    db.delete(row)
    db.commit()
    return {"detail": "공정이 삭제되었습니다."}


# =========================
# 루트 (공용)
# =========================
@app.get("/", tags=["공용 기능"])
async def root():
    """
    ▶ 서버 상태 확인 용도

    - 단순히 API 서버가 정상 동작 중인지 확인할 때 사용
    - 다중 현장(커뮤니티) 지원 버전
    """
    return {"message": "다중 현장 커뮤니티 기반 건설 출석 · 공지 · 도면 · 공정 관리 API 서버 동작 중"}


# =========================
# uvicorn 실행
# =========================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
@app.get("/public/sites", response_model=List[SiteRead])
async def public_sites(db: Session = Depends(get_db)):
    rows = db.query(SiteTable).filter(SiteTable.is_active == True).all()
    return [site_row_to_schema(r) for r in rows]
