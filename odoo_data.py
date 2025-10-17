
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
payload = {"dni":"12345678","name":"Juan","check_time":"2025-10-03 08:15:00","openMethod":"FINGERPRINT"}
res = models.execute_kw(DB, uid, API_KEY, 'hr.enhancement.api', 'attendance_webhook', [payload], {})
print(res)
