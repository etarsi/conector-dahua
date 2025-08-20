import requests

url = "https://test.sebigus.com.ar/hr_enhancement/attendance"
payload = {
    "dni": "96430726",
    "name": "Robert Brian Maldonado",
    "check_time": "2025-08-15 07:18:50.901",
    "openMethod": "FINGERPRINT"
}
r = requests.post(url, json=payload, timeout=10, verify=False) 
print(r.json())           # {'jsonrpc': '2.0', 'id': None, 'result': {...}}
res = r.json().get('result', {})
print(res.get('success'), res.get('message') or res.get('error'))
