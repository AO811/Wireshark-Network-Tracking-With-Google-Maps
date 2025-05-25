# 🌐 Wireshark Network Tracking with Google Maps

This project is a real-time cybersecurity tool that tracks IP addresses extracted from Wireshark packet captures (CSV format) and plots their geolocation data on an interactive map using **Folium**. It also integrates **IP threat detection** via external APIs and provides an **analytics dashboard** for threat intelligence.

---

### 📁 Project Structure
```yaml
.
├── ip_tracker_gui.py      # Main GUI Application using Tkinter
├── tracker.py             # Module to fetch geolocation and threat data (uses APIs)
├── analytics.py           # Analytics dashboard (Tkinter + Matplotlib)
├── geolocated_ips_gui_filtered.csv  # Output CSV file (auto-generated)
├── ip_map_gui_filtered.html         # Output map file (auto-generated)

```
---

### 🖥️ Features
- 📂 CSV File Input: Accepts .csv files exported from Wireshark (must contain Source and Destination columns).
- 🌍 Geolocation Mapping: Plots all unique IP addresses on a Folium map with colored markers based on threat status.
- 🚨 Threat Detection: Classifies IPs as Clean, Suspicious, or Malicious.
- 📊 Analytics Dashboard:
  - Threat distribution charts (pie/bar)
  - Top malicious IPs table
  - Protocol traffic analysis (based on Protocol column in CSV)
- 🌐 Country Filter: Filter map results by country.
- 📤 Export Reports: Save analyzed data as CSV.

---

### 📦 Requirements
#### 1. 🧰 Software & Tools
 - `Python 3.7+`
 - `Wireshark` – to capture network packets and export them as CSV

#### 2. 📥 Python Libraries
Install the required Python packages using pip:
```yaml
pip install pandas folium matplotlib requests
```

#### 3. 🌐 Internet Connectivity
Ensure there is an Internet connection for capturing IP traffic and for geolocation/threat API queries

---
### 🧪 Packet Capture Instructions
To use this tool effectively, you need to capture IP traffic using Wireshark and export the data:
  - Open Wireshark and start capturing on the desired network interface.
  - Once sufficient packets are captured, stop the capture.
  - Go to File → Export Packet Dissections → As CSV.
Ensure that the exported file includes at least the following columns:
  - `Source`
  - `Destination`
  - `Protocol` (for analytics features)
Save the file and use it in the application.

---

### ⚙️ How It Works

- `ip_tracker_gui.py`
  - Tkinter GUI that:
    - Loads a CSV file (Select CSV button)
    - Asynchronously fetches geolocation and threat info using tracker.py
    - Enables country filtering and interactive map generation
    - Launches an analytics dashboard from analytics.py

  - Map Features:
    - Uses folium.Map() + MarkerCluster
    - Adds a legend to explain color-coded threat levels
    - Generates ip_map_gui_filtered.html and auto-opens in browser

- `analytics.py`
  - Tkinter window launched from the main app:
    - Shows counts for each threat level
    - Lists Top 10 Malicious/Suspicious IPs
    - Visualizes:
      - Threat distribution (Pie Chart / Bar Chart)
      - Network protocol traffic (if Protocol column exists)
    - Allows the user to export the data as .csv

- `tracker.py`
  - Backend logic module responsible for:
    - Fetching geolocation data using external IP geolocation services
    - Querying AbuseIPDB or VirusTotal APIs to assess threat levels
    - Handling timeouts, API rate limits, and error cases gracefully
    - Returning enriched IP data with threat classification and location info
      
---
### 🌐 APIs Used

This project uses external APIs to fetch geolocation and threat intelligence data for the IP addresses found in the uploaded CSV file.

#### 1. 🌍 IP Geolocation API

- **Purpose**: To determine the approximate physical location (latitude, longitude, country, region, etc.) of each IP address.
- **Used In**: `tracker.py`
- **Typical API Providers**: 
  - [ip-api.com](https://ip-api.com/)
  - [ipgeolocation.io](https://ipgeolocation.io/)
  - [ipinfo.io](https://ipinfo.io/)

- **Response Fields Used**:
  - IP address
  - Country
  - Latitude & Longitude
  - Region or City (optional)

#### 2. 🚨 Threat Intelligence API

- **Purpose**: To classify IP addresses as `Clean`, `Suspicious`, `Malicious`, or `Unknown` based on reports and threat databases.
- **Used In**: `tracker.py`
- **APIs Integrated**:
  - **[AbuseIPDB](https://www.abuseipdb.com/)**: Checks the reputation of IPs and returns an abuse confidence score.
  - **[VirusTotal](https://www.virustotal.com/)** *(fallback)*: Provides community-based threat analysis and history of IPs.

- **Threat Scoring Logic**:
  - Abuse Confidence Score ≥ 85 → 🔴 Malicious
  - 40 ≤ Score < 85 → 🟠 Suspicious
  - Score < 40 → 🟢 Clean
  - No response or failure → 🔵 Unknown

- **Response Fields Used**:
  - Abuse confidence score
  - Country of IP origin
  - Number of reports
  - Last reported date (optional)

#### These APIs allow the app to:
- Place IPs on the map with accurate markers.
- Color-code IPs by threat level.
- Generate insights and threat visualizations in the analytics dashboard.

> 💡 **Note**: You need an internet connection for API calls to work, and some APIs may require you to sign up for a free API key.

---

### 🧠 Threat Level Color Codes
- Clean	🟢 Green
- Suspicious	🟠 Orange
- Malicious	🔴 Red

---

### 📝 Notes
- The input CSV must include at least the Source and Destination IP columns.
- For threat analytics to work fully, input should also have the Protocol column.
- Outputs:
  1. geolocated_ips_gui_filtered.csv: IPs with threat and geo info
  2. ip_map_gui_filtered.html: Map with clustered threat markers

---

### 🚀 How to Run
```yaml
python ip_tracker_gui.py
```

---

### 📸 Screenshots

- #### GUI Interface
<img src="https://github.com/user-attachments/assets/f46a2a6a-98f8-402a-8b0e-c97e53dd17b6" width="600"/>

---

- #### Generated Map with Colored Markers
<img src="https://github.com/user-attachments/assets/f45a1766-f66c-4f25-8d4e-f7c809ac16c0" width="400"/>  
<img src="https://github.com/user-attachments/assets/88397812-b6c1-40c4-b28b-6dce96c65a35" width="400"/>

---

- #### Analytics Dashboard (Charts & Tables)
<img src="https://github.com/user-attachments/assets/0128efda-57bf-46a2-891a-9b241e7b54b6" width="400"/>
<img src="https://github.com/user-attachments/assets/9c67c7a0-03d6-4848-bd12-7992c5d9b7c9" width="400"/>
<img src="https://github.com/user-attachments/assets/8e4724b1-385d-4611-a9cb-1a7e1e9759c8" width="400"/>
<img src="https://github.com/user-attachments/assets/21e6df12-75dd-42d1-aa63-9369de51636f" width="400"/>

---

### 🧪 Sample CSV File
A Wireshark-exported CSV file (sample_network_traffic.csv) has been uploaded to this repository for demonstration and testing purposes.

#### 1. ✅ Location: `sample_network_traffic.csv`
#### 2. 🧾 Includes Columns: No., Time, Source, Destination, Protocol, Length, Info
#### 3. 🔍 You can use this file to:
  - Test the application flow
  - Generate the geolocation map
  - View threat analytics dashboard
