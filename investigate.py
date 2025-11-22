# investigate.py
import pandas as pd

df = pd.read_csv('breach_events.csv', parse_dates=['ts'])
df = df.sort_values('ts')

def suspicious_downloads():
    print("=== Large Downloads ===")
    mask = df['action']=='download'
    big = df[mask & (df['bytes'] > 100*1024*1024)]
    if big.empty:
        print("None")
    else:
        print(big[['ts','user','ip','bytes']].to_string(index=False))

def suspect_ip_activity(ip):
    print(f"\n=== Activity for suspect IP {ip} ===")
    sub = df[df['ip']==ip]
    print(sub[['ts','user','action','bytes']].tail(20).to_string(index=False))

def compromised_accounts():
    # crude heuristic: many access_table or downloads shortly after success logins or failed attempts
    print("\n=== Accounts with abnormal downloads/accesses ===")
    counts = df.groupby('user').agg({
        'action': lambda x: (x=='download').sum(),
        'ip': 'nunique'
    }).rename(columns={'action':'downloads','ip':'unique_ips'})
    suspicious = counts[(counts['downloads']>=1) & (counts['unique_ips']>=2)].sort_values('downloads', ascending=False)
    if suspicious.empty:
        print("None")
    else:
        print(suspicious.to_string())

if __name__ == '__main__':
    suspicious_downloads()
    suspect_ip_activity('203.0.113.55')
    compromised_accounts()
