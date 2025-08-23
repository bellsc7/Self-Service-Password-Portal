คุณต้องใช้เครื่องมือ Active Directory Users and Computers เพื่อมอบสิทธิ์ (Delegate Control) ให้กับ Service Account ของคุณครับ

นี่คือขั้นตอนการทำ ซึ่งโดยทั่วไปจะทำบนเครื่อง Domain Controller ครับ

## วิธีการมอบสิทธิ์ (Delegate Control)
เปิด Active Directory Users and Computers (ADUC)

ไปที่ Server Manager -> Tools -> Active Directory Users and Computers

หรือกด Win + R, พิมพ์ dsa.msc แล้วกด Enter

เลือก OU ที่ต้องการ

ในหน้าต่าง ADUC, ค้นหาและคลิกขวาที่ OU (Organizational Unit) ที่เก็บ User Account ที่คุณต้องการให้ Service Account นี้จัดการได้

สำคัญ: คุณต้องเลือก OU ที่ถูกต้อง หาก User อยู่ใน OU อื่น Service Account ก็จะไม่มีสิทธิ์จัดการ

เลือก Delegate Control...

เริ่ม Wizard

จะปรากฏหน้าต่าง Delegation of Control Wizard ขึ้นมา ให้กด Next

เลือก Service Account

กดปุ่ม Add...

พิมพ์ชื่อ Service Account ของคุณลงไป แล้วกด Check Names เพื่อค้นหา

เมื่อเจอแล้ว กด OK แล้วกด Next

เลือก Task ที่จะมอบสิทธิ์ (Tasks to Delegate)

ในหน้านี้ ให้เลือก Create a custom task to delegate เพื่อกำหนดสิทธิ์ได้ละเอียดที่สุด แล้วกด Next

เลือก Only the following objects in the folder แล้วติ๊กที่ User objects ด้านล่าง จากนั้นกด Next

กำหนดสิทธิ์ (Permissions)

ในหน้านี้ ให้ติ๊กที่ General และ Property-specific

ในรายการ Permissions ให้มองหาสิทธิ์ที่จำเป็นและติ๊กที่ช่อง Read และ/หรือ Write:

Reset Password (ติ๊กอันนี้อันเดียวก็ครอบคลุมการรีเซ็ตรหัสผ่านแล้ว)

Read mail (เพื่อให้ API อ่านอีเมลได้)

Read lockoutTime (เพื่อตรวจสอบสถานะล็อก)

Write lockoutTime (เพื่อปลดล็อกบัญชี)

ติ๊กสิทธิ์อื่นๆ ที่จำเป็นตามที่คุณต้องการ

เสร็จสิ้น

กด Next และ Finish เพื่อสิ้นสุดการตั้งค่า

