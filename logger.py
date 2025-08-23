import logging
from logging.handlers import RotatingFileHandler

# 1. สร้าง Logger object หลัก
logger = logging.getLogger("ad_self_service_logger")
logger.setLevel(logging.INFO)

# 2. กำหนดรูปแบบของ Log (Format)
log_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)

# 3. สร้าง Handler สำหรับเขียน Log ลงไฟล์
# RotatingFileHandler จะสร้างไฟล์ใหม่เมื่อไฟล์ปัจจุบันมีขนาดใหญ่เกินไป
file_handler = RotatingFileHandler(
    'app.log',          # ชื่อไฟล์
    maxBytes=5*1024*1024, # ขนาดสูงสุด 5 MB
    backupCount=2       # เก็บไฟล์เก่าไว้ 2 ไฟล์
)
file_handler.setFormatter(log_formatter)

# 4. สร้าง Handler สำหรับแสดง Log บนหน้าจอ Console
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)

# 5. เพิ่ม Handlers เข้าไปใน Logger หลัก
logger.addHandler(file_handler)
logger.addHandler(stream_handler)