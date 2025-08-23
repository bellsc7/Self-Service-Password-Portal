import os
import ssl
from dotenv import load_dotenv
from ldap3 import Server, Connection, Tls, ALL, MODIFY_REPLACE
from logger import logger

# โหลดค่าจากไฟล์ .env
load_dotenv()

# อ่านค่าการตั้งค่าจาก environment variables
AD_SERVER = os.getenv("AD_SERVER")
AD_PORT = int(os.getenv("AD_PORT", 636))
AD_USER = os.getenv("AD_USER")
AD_PASSWORD = os.getenv("AD_PASSWORD")
AD_SEARCH_BASE = os.getenv("AD_SEARCH_BASE")

def get_ad_connection():
    """
    สร้างและคืนค่า connection object ไปยัง Active Directory พร้อม logging ที่ละเอียดขึ้น
    """
    logger.debug(f"Attempting to connect to AD server: {AD_SERVER}:{AD_PORT} with user: {AD_USER}")
    try:
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(
            AD_SERVER,
            port=AD_PORT,
            use_ssl=True,
            tls=tls_config,
            get_info=ALL
        )
        conn = Connection(
            server,
            user=AD_USER,
            password=AD_PASSWORD,
            auto_bind=True,
            raise_exceptions=True
        )
        if not conn.bound:
            logger.error(f"AD Bind failed. Result: {conn.result}")
            raise Exception(f"Bind failed: {conn.result}")
        
        logger.debug("Successfully connected and bound to AD with service account.")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect or bind to AD. Specific Error: {e}", exc_info=True)
        return None

def find_user_email(username: str) -> str | None:
    """
    ค้นหาอีเมลของผู้ใช้ใน AD จาก sAMAccountName
    โดยจะค้นหาจาก attribute 'pager' ก่อน หากไม่เจอจึงจะค้นหาจาก 'mail'
    """
    conn = get_ad_connection()
    if not conn:
        return None

    try:
        search_filter = f'(sAMAccountName={username})'
        conn.search(
            search_base=AD_SEARCH_BASE,
            search_filter=search_filter,
            attributes=['pager', 'mail']
        )
        if conn.entries:
            user_entry = conn.entries[0]
            if 'pager' in user_entry and user_entry.pager.value:
                return user_entry.pager.value
            if 'mail' in user_entry and user_entry.mail.value:
                return user_entry.mail.value
        return None
    finally:
        if conn and conn.bound:
            conn.unbind()

def reset_user_password(username: str, new_password: str) -> bool:
    """
    ค้นหาผู้ใช้และรีเซ็ตรหัสผ่านใน AD
    """
    conn = get_ad_connection()
    if not conn:
        return False
    try:
        search_filter = f'(sAMAccountName={username})'
        conn.search(search_base=AD_SEARCH_BASE, search_filter=search_filter, attributes=['distinguishedName'])
        if not conn.entries:
            return False
        user_dn = conn.entries[0].distinguishedName.value
        encoded_password = f'"{new_password}"'.encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]})
        return conn.result['result'] == 0
    finally:
        if conn and conn.bound:
            conn.unbind()

def unlock_user_account(username: str) -> bool:
    """
    ค้นหาผู้ใช้และปลดล็อกบัญชี
    """
    conn = get_ad_connection()
    if not conn:
        return False
    try:
        search_filter = f'(sAMAccountName={username})'
        conn.search(search_base=AD_SEARCH_BASE, search_filter=search_filter, attributes=['distinguishedName'])
        if not conn.entries:
            return False
        user_dn = conn.entries[0].distinguishedName.value
        conn.modify(user_dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]})
        return conn.result['result'] == 0
    finally:
        if conn and conn.bound:
            conn.unbind()

def update_user_pager(username: str, new_pager_value: str) -> bool:
    """
    อัปเดตค่าใน attribute 'pager' ของผู้ใช้
    """
    conn = get_ad_connection()
    if not conn:
        return False
    try:
        search_filter = f'(sAMAccountName={username})'
        conn.search(search_base=AD_SEARCH_BASE, search_filter=search_filter, attributes=['distinguishedName'])
        if not conn.entries:
            return False
        user_dn = conn.entries[0].distinguishedName.value
        conn.modify(user_dn, {'pager': [(MODIFY_REPLACE, [new_pager_value])]})
        return conn.result['result'] == 0
    finally:
        if conn and conn.bound:
            conn.unbind()