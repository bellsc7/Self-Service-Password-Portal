import os
# ▼▼▼ 1. เปลี่ยน import หลัก ▼▼▼
from redis import asyncio as redis
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# ▼▼▼ 2. สร้าง client แบบ Asynchronous ▼▼▼
try:
    # สร้าง client ที่พร้อมใช้งานแบบ async
    redis_client = redis.from_url(
        f"redis://{REDIS_HOST}:{REDIS_PORT}",
        decode_responses=True # ทำให้ผลลัพธ์เป็น string แทน bytes
    )
    print("Redis client configured for async connection.")

except Exception as e:
    print(f"Error configuring Redis client: {e}")
    redis_client = None