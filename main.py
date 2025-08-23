import os
import ssl
import requests # ◀◀◀ เพิ่ม import
from fastapi import FastAPI, HTTPException, status, Request, Depends
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from typing import Optional

# --- JWT and Security ---
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

# --- Our Services ---
from ad_connector import find_user_email, reset_user_password, unlock_user_account, update_user_pager, get_ad_connection
from notification_service import generate_otp, send_otp_email
from redis_client import redis_client
from logger import logger

# --- Rate Limiter ---
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# --- LDAP ---
from ldap3 import Server, Connection, Tls

# --- Settings ---
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key_if_not_set")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY") # ◀◀◀ อ่านค่า reCAPTCHA
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# --- FastAPI App ---
app = FastAPI(
    title="Active Directory Self-Service API",
    description="API for managing AD user passwords and accounts.",
    version="3.1.0" # reCAPTCHA Feature Version
)

# --- CORS Middleware ---
from fastapi.middleware.cors import CORSMiddleware
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Rate Limiter Startup ---
@app.on_event("startup")
async def startup():
    if redis_client:
        await FastAPILimiter.init(redis_client)
    else:
        logger.error("Could not initialize RateLimiter due to missing Redis connection.")

# --- Models ---
class ForgotPasswordRequest(BaseModel):
    username: str = Field(..., example="johndoe")
    recaptcha_token: str # ◀◀◀ เพิ่มฟิลด์นี้

class UnlockAccountRequest(BaseModel):
    username: str = Field(..., example="johndoe")
    recaptcha_token: str # ◀◀◀ เพิ่มฟิลด์นี้

class ResetPasswordRequest(BaseModel):
    username: str = Field(..., example="johndoe")
    otp: str = Field(..., example="123456")
    new_password: str = Field(..., example="P@ssw0rd123!")

class UnlockAccountConfirmRequest(BaseModel):
    username: str = Field(..., example="johndoe")
    otp: str = Field(..., example="123456")

class LoginRequest(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    displayName: Optional[str] = None
    email: Optional[str] = None
    telephone: Optional[str] = None
    personal_email: Optional[str] = None

class UpdateProfileRequest(BaseModel):
    personal_email: str

# --- Helper functions ---
def verify_recaptcha(token: str, client_ip: str) -> bool:
    if not RECAPTCHA_SECRET_KEY:
        logger.error("RECAPTCHA_SECRET_KEY is not set in .env file.")
        return False
    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": RECAPTCHA_SECRET_KEY,
                "response": token,
                "remoteip": client_ip,
            },
        )
        result = response.json()
        logger.info(f"reCAPTCHA verification result: {result}")
        return result.get("success", False)
    except Exception as e:
        logger.error(f"Error during reCAPTCHA verification: {e}")
        return False
    

# --- JWT Helper Functions ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

# --- Main Endpoint ---
@app.get("/")
def read_root():
    return {"status": "ok", "message": "Welcome to AD Self-Service API!"}

# --- Authentication Endpoint ---
@app.post("/api/auth/login", dependencies=[Depends(RateLimiter(times=10, minutes=5))])
async def login_for_access_token(form_data: LoginRequest, request: Request):
    client_ip = request.client.host
    logger.info(f"LOGIN_ATTEMPT for user '{form_data.username}' from IP '{client_ip}'")
    service_conn = get_ad_connection()
    if not service_conn:
        raise HTTPException(status_code=500, detail="Cannot connect to AD with service account.")
    
    AD_SEARCH_BASE = os.getenv("AD_SEARCH_BASE")
    search_filter = f'(sAMAccountName={form_data.username})'
    service_conn.search(search_base=AD_SEARCH_BASE, search_filter=search_filter, attributes=['distinguishedName'])
    if not service_conn.entries:
        logger.warning(f"LOGIN_FAILED for user '{form_data.username}': User not found.")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    user_dn = service_conn.entries[0].distinguishedName.value
    service_conn.unbind()
    
    try:
        AD_SERVER = os.getenv("AD_SERVER")
        AD_PORT = int(os.getenv("AD_PORT", 636))
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        user_server = Server(AD_SERVER, port=AD_PORT, use_ssl=True, tls=tls_config)
        user_conn = Connection(user_server, user=user_dn, password=form_data.password, auto_bind=True)
        if not user_conn.bound:
            logger.warning(f"LOGIN_FAILED for user '{form_data.username}': Invalid password.")
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        user_conn.unbind()
    except Exception as e:
        logger.error(f"LOGIN_EXCEPTION for user '{form_data.username}': {e}")
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": form_data.username})
    logger.info(f"LOGIN_SUCCESS for user '{form_data.username}'")
    return {"access_token": access_token, "token_type": "bearer"}

# --- User Profile Endpoints ---
@app.get("/api/user/me", response_model=UserProfile)
async def read_users_me(current_username: str = Depends(get_current_user)):
    conn = get_ad_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Cannot connect to AD")
    
    AD_SEARCH_BASE = os.getenv("AD_SEARCH_BASE")
    search_filter = f'(sAMAccountName={current_username})'
    attributes_to_get = ['displayName', 'mail', 'telephoneNumber', 'pager']
    conn.search(search_base=AD_SEARCH_BASE, search_filter=search_filter, attributes=attributes_to_get)
    
    if not conn.entries:
        raise HTTPException(status_code=404, detail="User not found")
        
    user_entry = conn.entries[0]
    conn.unbind()
    
    return UserProfile(
        displayName=user_entry.displayName.value if 'displayName' in user_entry else None,
        email=user_entry.mail.value if 'mail' in user_entry else None,
        telephone=user_entry.telephoneNumber.value if 'telephoneNumber' in user_entry else None,
        personal_email=user_entry.pager.value if 'pager' in user_entry else None,
    )

@app.put("/api/user/me")
async def update_users_me(profile_update: UpdateProfileRequest, current_username: str = Depends(get_current_user), request: Request = None):
    client_ip = request.client.host if request else "N/A"
    logger.info(f"UPDATE_PROFILE_ATTEMPT for user '{current_username}' from IP '{client_ip}'")
    success = update_user_pager(username=current_username, new_pager_value=profile_update.personal_email)
    if not success:
        logger.error(f"UPDATE_PROFILE_FAILED for user '{current_username}'")
        raise HTTPException(status_code=500, detail="Failed to update personal email in AD.")
    
    logger.info(f"UPDATE_PROFILE_SUCCESS for user '{current_username}'")
    return {"status": "success", "message": "Personal email updated successfully."}

# --- Password Reset & Unlock Endpoints ---

@app.post("/api/password/forgot-request", dependencies=[Depends(RateLimiter(times=3, minutes=5))])
async def request_password_reset(request_data: ForgotPasswordRequest, request: Request):
    client_ip = request.client.host
    username = request_data.username
    logger.info(f"PASSWORD_RESET_REQUEST from IP '{client_ip}' for user '{username}'")
    user_email = find_user_email(username)
    if not user_email:
        logger.warning(f"PASSWORD_RESET_REQUEST_NOT_FOUND from IP '{client_ip}' for user '{username}' (User not in AD or no email)")
        return {"status": "success", "message": f"If an account with username '{username}' exists, an OTP will be sent."}
    otp_code = generate_otp()
    await redis_client.setex(f"otp:reset:{username.lower()}", 300, otp_code)
    email_sent = send_otp_email(recipient_email=user_email, otp_code=otp_code)
    if not email_sent:
        logger.error(f"EMAIL_SEND_FAILURE for user '{username}' to email '{user_email}'")
        raise HTTPException(status_code=500, detail="Could not send OTP email.")
    logger.info(f"OTP_SENT_SUCCESS for password reset to user '{username}' from IP '{client_ip}'")
    return {"status": "success", "message": f"An OTP has been sent to the email associated with '{username}'."}

@app.post("/api/password/reset", dependencies=[Depends(RateLimiter(times=10, minutes=5))])
async def verify_otp_and_reset_password(request_data: ResetPasswordRequest, request: Request):
    client_ip = request.client.host
    username = request_data.username
    key = f"otp:reset:{username.lower()}"
    stored_otp = await redis_client.get(key)
    if not stored_otp or stored_otp != request_data.otp:
        logger.warning(f"INVALID_OTP_RESET_ATTEMPT from IP '{client_ip}' for user '{username}'")
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    success = reset_user_password(username=username, new_password=request_data.new_password)
    await redis_client.delete(key)
    if not success:
        logger.error(f"AD_PASSWORD_RESET_FAILED from IP '{client_ip}' for user '{username}'")
        raise HTTPException(status_code=500, detail="Failed to reset password in AD. The new password might not meet the complexity requirements.")
    logger.info(f"PASSWORD_RESET_SUCCESS from IP '{client_ip}' for user '{username}'")
    return {"status": "success", "message": "Your password has been reset successfully."}

@app.post("/api/account/unlock-request", dependencies=[Depends(RateLimiter(times=3, minutes=5))])
async def request_account_unlock(request_data: UnlockAccountRequest, request: Request):
    client_ip = request.client.host
    if not verify_recaptcha(request_data.recaptcha_token, client_ip):
        logger.warning(f"RECAPTCHA_FAILED for unlock request from IP '{client_ip}'")
        raise HTTPException(status_code=400, detail="reCAPTCHA verification failed. Please try again.")

    username = request_data.username
    logger.info(f"UNLOCK_REQUEST from IP '{client_ip}' for user '{username}'")
    user_email = find_user_email(username)
    if not user_email:
        return {"status": "success", "message": f"If an account with username '{username}' exists, an unlock code will be sent."}

    otp_code = generate_otp()
    await redis_client.setex(f"otp:unlock:{username.lower()}", 300, otp_code)
    send_otp_email(recipient_email=user_email, otp_code=otp_code)
    
    logger.info(f"OTP_SENT_SUCCESS for unlock to user '{username}' from IP '{client_ip}'")
    return {"status": "success", "message": f"An unlock code has been sent to the email associated with '{username}'."}

async def request_account_unlock(request_data: UnlockAccountRequest, request: Request):
    client_ip = request.client.host
    username = request_data.username
    logger.info(f"UNLOCK_REQUEST from IP '{client_ip}' for user '{username}'")
    user_email = find_user_email(username)
    if not user_email:
        logger.warning(f"UNLOCK_REQUEST_NOT_FOUND from IP '{client_ip}' for user '{username}' (User not in AD or no email)")
        return {"status": "success", "message": f"If an account with username '{username}' exists, an unlock code will be sent."}
    otp_code = generate_otp()
    await redis_client.setex(f"otp:unlock:{username.lower()}", 300, otp_code)
    email_sent = send_otp_email(recipient_email=user_email, otp_code=otp_code)
    if not email_sent:
        logger.error(f"EMAIL_SEND_FAILURE for user '{username}' to email '{user_email}'")
        raise HTTPException(status_code=500, detail="Could not send unlock OTP email.")
    logger.info(f"OTP_SENT_SUCCESS for unlock to user '{username}' from IP '{client_ip}'")
    return {"status": "success", "message": f"An unlock code has been sent to the email associated with '{username}'."}

@app.post("/api/account/unlock-confirm", dependencies=[Depends(RateLimiter(times=10, minutes=5))])
async def verify_otp_and_unlock_account(request_data: UnlockAccountConfirmRequest, request: Request):
    client_ip = request.client.host
    username = request_data.username
    key = f"otp:unlock:{username.lower()}"
    stored_otp = await redis_client.get(key)
    if not stored_otp or stored_otp != request_data.otp:
        logger.warning(f"INVALID_OTP_UNLOCK_ATTEMPT from IP '{client_ip}' for user '{username}'")
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    success = unlock_user_account(username=username)
    await redis_client.delete(key)
    if not success:
        logger.error(f"AD_UNLOCK_FAILED from IP '{client_ip}' for user '{username}'")
        raise HTTPException(status_code=500, detail="Failed to unlock account in AD.")
    logger.info(f"ACCOUNT_UNLOCK_SUCCESS from IP '{client_ip}' for user '{username}'")
    return {"status": "success", "message": "Your account has been unlocked successfully."}