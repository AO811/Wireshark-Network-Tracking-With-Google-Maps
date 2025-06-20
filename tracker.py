import pandas as pd
import time
import requests
import ipaddress

# AbuseIPDB API key 
API_KEY = "9e0fe4e4affff1b167324cb8622c76f2f7edcc762e97dba7c53ce87ab100ea6723108c3119e2d57a"
# VirusTotal API key
VT_API_KEY = "bdc3b479bc16a76d89946f799d5b26dc165f3285b4c9a7e795993d78d56ae649"

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

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

def check_ip_virustotal(ip, api_key=VT_API_KEY):
    try:
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            if malicious > 0:
                return "Malicious (VT)", malicious
            elif suspicious > 0:
                return "Suspicious (VT)", suspicious
            else:
                return "Clean (VT)", 0
        return "Unknown (VT)", 0
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return "Unknown (VT)", 0

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
                if threat_status == 'Unknown':
                   threat_status, abuse_score = check_ip_virustotal(ip)
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
