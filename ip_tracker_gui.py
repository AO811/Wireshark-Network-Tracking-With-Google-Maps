import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import folium
from folium.plugins import MarkerCluster
import webbrowser
import os

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
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if file_path:
        global geo_results
        geo_results = fetch_ip_data(file_path)
        countries = sorted(set(item['Country'] for item in geo_results))
        country_menu['values'] = ["All Countries"] + countries
        country_menu.current(0)
        generate_button.config(state="normal")

def generate_map():
    selected_country = country_var.get()
    filtered = geo_results if selected_country == "All Countries" else [
        ip for ip in geo_results if ip['Country'] == selected_country
    ]

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
                f"<b>Abuse Score:</b> {ip_data['Abuse Score']}<br>"
                f"<b>Total Reports:</b> {ip_data.get('Total Reports', 0)}<br>"
                f"<b>Domain:</b> {ip_data.get('Domain', 'N/A')}<br>"
                f"<b>Whitelisted:</b> {ip_data.get('Whitelisted', False)}"
                )

        folium.Marker(
            location=[ip_data['Latitude'], ip_data['Longitude']],
            popup=folium.Popup(popup, max_width=300),
            icon=folium.Icon(color=get_marker_color(ip_data['Threat Status']), icon='globe')
        ).add_to(marker_cluster)

    filename = "ip_map_gui_filtered.html"
    pd.DataFrame(filtered).to_csv("geolocated_ips_gui_filtered.csv", index=False)
    world_map.save(filename)
    webbrowser.open('file://' + os.path.realpath(filename))
    messagebox.showinfo("Map Created", f"Filtered map generated for {selected_country}!")

# GUI setup
root = tk.Tk()
root.title("Wireshark IP Tracker with Map")
root.geometry("500x350")

tk.Label(root, text="Wireshark IP Tracker with Map", font=("Arial", 14, "bold")).pack(pady=10)
tk.Button(root, text="Select CSV File", command=open_file, width=25, height=2, bg="#4CAF50", fg="white").pack(pady=5)

tk.Label(root, text="Select Country to Filter:").pack(pady=5)
country_var = tk.StringVar()
country_menu = ttk.Combobox(root, textvariable=country_var, state="readonly", width=40)
country_menu.pack()

generate_button = tk.Button(root, text="Generate Map", command=generate_map, state="disabled", width=25, height=2, bg="#2196F3", fg="white")
generate_button.pack(pady=10)

tk.Button(root, text="Show Analytics", command=lambda: show_analytics(geo_results, file_path), width=25, height=2, bg="#9C27B0", fg="white").pack(pady=5)

tk.Label(root, text="CSV must have 'Source' and 'Destination' columns.", font=("Arial", 9)).pack(pady=5)

root.mainloop()
