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

### 🧠 Threat Level Color Codes
- Clean	🟢 Green
- Suspicious	🟠 Orange
- Malicious	🔴 Red
- Unknown	🔵 Blue

---

### 📌 Requirements
Install required Python packages via pip:
```yaml
pip install pandas folium matplotlib
```
Also ensure you have:
Wireshark (to generate .csv packet captures)
Internet connection (for geolocation/threat API queries)

---

### 📝 Notes
- Input CSV must include at least Source and Destination IP columns.
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

- The GUI interface
  ![image](https://github.com/user-attachments/assets/f46a2a6a-98f8-402a-8b0e-c97e53dd17b6)


- Generated map with colored markers
 ![image](https://github.com/user-attachments/assets/f45a1766-f66c-4f25-8d4e-f7c809ac16c0)

 ![image](https://github.com/user-attachments/assets/4e3ea78b-c31a-4712-a2a9-218e4a2c113b)



- Analytics dashboard (charts & tables)

