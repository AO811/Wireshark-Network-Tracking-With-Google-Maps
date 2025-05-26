import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import folium
from folium.plugins import MarkerCluster
import webbrowser
import os
import threading

from tracker import fetch_ip_data
from analytics import show_analytics

geo_results = []
file_path = None

def get_marker_color(threat_status):
    return {
        "Malicious": "red",
        "Suspicious": "orange",
        "Clean": "green"
    }.get(threat_status, "blue")

def open_file():
    global geo_results, file_path
    file_path = filedialog.askopenfilename(filetypes=[("CSV or PCAP Files", "*.csv *.pcap")])
    if not file_path:
        return

    select_button.config(state="disabled")
    generate_button.config(state="disabled")
    analytics_button.config(state="disabled")
    status_label.config(text="⏳ Fetching geolocation & threat data…")

    thread = threading.Thread(target=threaded_fetch)
    thread.daemon = True
    thread.start()

def threaded_fetch():
    global geo_results
    try:
        geo_results = fetch_ip_data(file_path)
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("Error", f"Failed to fetch IP data:\n{e}"))
        root.after(0, reset_ui)
        return

    countries = sorted({item["Country"] for item in geo_results})
    root.after(0, lambda: update_ui_after_fetch(countries))

def update_ui_after_fetch(countries):
    country_menu['values'] = ["All Countries"] + countries
    country_menu.current(0)

    select_button.config(state="normal")
    generate_button.config(state="normal")
    analytics_button.config(state="normal")
    status_label.config(text="✅ Ready")

def reset_ui():
    select_button.config(state="normal")
    generate_button.config(state="disabled")
    analytics_button.config(state="disabled")
    status_label.config(text="")

def generate_map():
    selected_country = country_var.get()
    filtered = (
        geo_results
        if selected_country == "All Countries"
        else [ip for ip in geo_results if ip["Country"] == selected_country]
    )

    if not filtered:
        messagebox.showinfo("No Data", f"No IPs found for {selected_country}.")
        return

    world_map = folium.Map(location=[20, 0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(world_map)

    for ip_data in filtered:
        popup = (
            f"<b>IP:</b> {ip_data['IP']}<br>"
            f"<b>City:</b> {ip_data['City']}<br>"
            f"<b>Region:</b> {ip_data['Region']}<br>"
            f"<b>Country:</b> {ip_data['Country']}<br>"
            f"<b>ISP:</b> {ip_data['ISP']}<br>"
            f"<b>Timezone:</b> {ip_data['Timezone']}<br>"
            f"<b>Threat:</b> {ip_data['Threat Status']}<br>"
            f"<b>Abuse Score:</b> {ip_data['Abuse Score']}"
        )
        folium.Marker(
            location=[ip_data['Latitude'], ip_data['Longitude']],
            popup=folium.Popup(popup, max_width=300),
            icon=folium.Icon(color=get_marker_color(ip_data['Threat Status']), icon='globe')
        ).add_to(marker_cluster)

    legend_html = """
     <div style="position: fixed; 
                 bottom: 50px; left: 50px; width: 180px; height: 110px; 
                 border:2px solid grey; z-index:9999; font-size:14px;
                 background-color:white; padding:10px;">
     <b>Threat Legend</b><br>
     <i style="color:green;">●</i> Clean<br>
     <i style="color:orange;">●</i> Suspicious<br>
     <i style="color:red;">●</i> Malicious
     </div>
     """
    world_map.get_root().html.add_child(folium.Element(legend_html))

    pd.DataFrame(filtered).to_csv("geolocated_ips_gui_filtered.csv", index=False)
    filename = "ip_map_gui_filtered.html"
    world_map.save(filename)
    webbrowser.open('file://' + os.path.realpath(filename))
    messagebox.showinfo("Map Created", f"Filtered map generated for {selected_country}!")

# ---------------------- GUI setup ---------------------- #
root = tk.Tk()
root.title("Wireshark IP Tracker")
root.geometry("520x460")
root.configure(bg="#1e1e2f")

style = ttk.Style()
style.theme_use("clam")
style.configure("TCombobox", fieldbackground="#1e1e2f", background="#2e2e3e", foreground="white")

frame = tk.Frame(root, bg="#1e1e2f")
frame.pack(pady=20)

tk.Label(
    frame, text="🌐 Wireshark IP Tracker with Map",
    font=("Segoe UI", 16, "bold"), bg="#1e1e2f", fg="#00FFD1"
).pack(pady=10)

select_button = tk.Button(
    frame, text="📂 Select CSV",
    command=open_file, width=30, height=2,
    bg="#00b894", fg="black", activebackground="#00cec9", font=("Segoe UI", 10, "bold")
)
select_button.pack(pady=5)

tk.Label(frame, text="🌍 Filter by Country:", font=("Segoe UI", 10, "bold"), bg="#1e1e2f", fg="#ffffff").pack(pady=(10, 2))
country_var = tk.StringVar()
country_menu = ttk.Combobox(frame, textvariable=country_var, state="readonly", width=42)
country_menu.pack()

generate_button = tk.Button(
    frame, text="🗺️ Generate Map",
    command=generate_map, state="disabled",
    width=30, height=2,
    bg="#0984e3", fg="white", activebackground="#74b9ff", font=("Segoe UI", 10, "bold")
)
generate_button.pack(pady=10)

analytics_button = tk.Button(
    frame, text="📊 Show Analytics",
    command=lambda: show_analytics(geo_results, file_path), state="disabled",
    width=30, height=2,
    bg="#6c5ce7", fg="white", activebackground="#a29bfe", font=("Segoe UI", 10, "bold")
)
analytics_button.pack(pady=5)

tk.Label(
    frame, text="* File must contain 'Source' and 'Destination' columns",
    font=("Segoe UI", 9), bg="#1e1e2f", fg="#888"
).pack(pady=5)

status_label = tk.Label(frame, text="", font=("Segoe UI", 10, "italic"), bg="#1e1e2f", fg="#00FF99")
status_label.pack(pady=5)

root.mainloop()
