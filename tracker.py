# tracker.py
import pandas as pd
import time
import requests

# AbuseIPDB API key - replace with your actual key
API_KEY = "9e0fe4e4affff1b167324cb8622c76f2f7edcc762e97dba7c53ce87ab100ea6723108c3119e2d57a"

def is_public_ip(ip):
    private_prefixes = (
        '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
        '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
        '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.'
    )
    return not ip.startswith(private_prefixes)

def check_ip_threat_abuseipdb(ip, api_key=API_KEY):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": api_key}
        response = requests.get(url, headers=headers, params=querystring)
        data = response.json().get('data', {})
        abuse_score = data.get('abuseConfidenceScore', 0)
        if abuse_score > 50:
            return 'Malicious', abuse_score
        elif abuse_score > 10:
            return 'Suspicious', abuse_score
        return 'Clean', abuse_score
    except:
        return 'Unknown', 0

def fetch_ip_data(file_path):
    geo_results = []
    df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip')
    ip_list = set(df['Source']).union(set(df['Destination']))
    ip_list = [ip for ip in ip_list if isinstance(ip, str) and is_public_ip(ip)]

    for ip in ip_list:
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}").json()
            if response['status'] == 'success':
                threat_status, abuse_score = check_ip_threat_abuseipdb(ip)
                geo_results.append({
                    'IP': ip,
                    'City': response.get('city', 'Unknown'),
                    'Region': response.get('regionName', 'Unknown'),
                    'Country': response.get('country', 'Unknown'),
                    'ISP': response.get('isp', 'Unknown'),
                    'Timezone': response.get('timezone', 'Unknown'),
                    'Latitude': response['lat'],
                    'Longitude': response['lon'],
                    'Threat Status': threat_status,
                    'Abuse Score': abuse_score
                })
            time.sleep(1)
        except Exception as e:
            print(f"IP {ip} error: {e}")
            continue
    return geo_results
