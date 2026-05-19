
import xmlrpc.client

URL = "https://one.sebigus.com.ar"
DB = "one"
USER = "rrhh@sebigus.com.ar"
API_KEY = "123"

common = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/common")
uid = common.authenticate(DB, USER, API_KEY, {})
assert uid, "Autenticación falló"
models = xmlrpc.client.ServerProxy(f"{URL}/xmlrpc/2/object")
print("UID:", uid)
print("api model exists:", models.execute_kw(DB, uid, API_KEY, 'ir.model', 'search', [[('model','=','hr.enhancement.api')]]))
print("api read right?:", models.execute_kw(DB, uid, API_KEY, 'hr.enhancement.api', 'check_access_rights', ['read'], {'raise_exception': False}))
payload = {"dni":"96175064","name":"Niño Blanco Samuel Isaac","check_time":"2026-04-23 06:55:00","openMethod":"FACE_RECOGNITION"}
res = models.execute_kw(DB, uid, API_KEY, 'hr.enhancement.api', 'attendance_webhook', [payload], {})
print(res)
