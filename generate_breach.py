# generate_breach.py
import pandas as pd
from datetime import datetime, timedelta
import random

rows = []
now = datetime.utcnow()
users = ['alice','bob','carol','dave','system']
ips = ['198.51.100.5','203.0.113.55','192.0.2.20','198.51.100.101']
for i in range(300):
    ts = (now - timedelta(minutes=300-i)).isoformat()
    user = random.choice(users)
    ip = random.choice(ips)
    # simulate an attacker using 'dave' account starting at index ~200
    if i > 220:
        user = 'dave'
        ip = '203.0.113.55'  # suspect ip
        action = random.choices(['login_failed','login_success','access_table','download'], [0.1,0.4,0.3,0.2])[0]
    else:
        action = random.choices(['login_success','login_failed','access_table','download'], [0.6,0.1,0.2,0.1])[0]
    bytes_sent = 0
    if action == 'download':
        bytes_sent = random.choice([1024, 2048, 5120000, 200000000])  # some big files
    rows.append({'ts':ts,'user':user,'ip':ip,'action':action,'bytes':bytes_sent})

df = pd.DataFrame(rows)
df.to_csv('breach_events.csv', index=False)
print("Generated breach_events.csv with", len(df), "rows")
