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
    """
    1. Ask user to pick a CSV.
    2. Disable buttons and show "Fetching..." status.
    3. Start a background thread to call fetch_ip_data().
    """
    global geo_results, file_path
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return

    # Disable buttons while fetching
    select_button.config(state="disabled")
    generate_button.config(state="disabled")
    analytics_button.config(state="disabled")
    status_label.config(text="Fetching geolocation & threat data…")

    # Start background thread
    thread = threading.Thread(target=threaded_fetch)
    thread.daemon = True
    thread.start()

def threaded_fetch():
    """
    Runs in a separate thread:
    1. Call fetch_ip_data() to populate geo_results.
    2. Extract unique countries.
    3. Use root.after() to update UI on the main thread.
    """
    global geo_results
    try:
        # This can take time if there are many IPs
        geo_results = fetch_ip_data(file_path)
    except Exception as e:
        # If something went wrong, show an error on the main thread
        root.after(0, lambda: messagebox.showerror("Error", f"Failed to fetch IP data:\n{e}"))
        # Re-enable buttons and clear status
        root.after(0, reset_ui)
        return

    # Prepare country list (unique + sorted)
    countries = sorted({item["Country"] for item in geo_results})
    root.after(0, lambda: update_ui_after_fetch(countries))

def update_ui_after_fetch(countries):
    """
    Called on the main thread via root.after().
    1. Populate the country_menu.
    2. Re-enable buttons.
    3. Update status label.
    """
    country_menu['values'] = ["All Countries"] + countries
    country_menu.current(0)

    select_button.config(state="normal")
    generate_button.config(state="normal")
    analytics_button.config(state="normal")
    status_label.config(text="Ready")

def reset_ui():
    """
    In case of error during fetch, re-enable everything and clear status.
    """
    select_button.config(state="normal")
    generate_button.config(state="disabled")
    analytics_button.config(state="disabled")
    status_label.config(text="")

def generate_map():
    """
    Build and display the Folium map filtered by selected country.
    """
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

    # Add custom legend
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

    # Save filtered CSV and HTML map
    pd.DataFrame(filtered).to_csv("geolocated_ips_gui_filtered.csv", index=False)
    filename = "ip_map_gui_filtered.html"
    world_map.save(filename)
    webbrowser.open('file://' + os.path.realpath(filename))
    messagebox.showinfo("Map Created", f"Filtered map generated for {selected_country}!")

# ---------------------- GUI setup ---------------------- #
root = tk.Tk()
root.title("Wireshark IP Tracker with Map")
root.geometry("500x380")

# Title label
tk.Label(root, text="Wireshark IP Tracker with Map", font=("Arial", 14, "bold")).pack(pady=10)

# Select CSV button
select_button = tk.Button(
    root,
    text="Select CSV File",
    command=open_file,
    width=25,
    height=2,
    bg="#4CAF50",
    fg="white"
)
select_button.pack(pady=5)

# Country filter dropdown
tk.Label(root, text="Select Country to Filter:").pack(pady=5)
country_var = tk.StringVar()
country_menu = ttk.Combobox(root, textvariable=country_var, state="readonly", width=40)
country_menu.pack()

# Generate Map button
generate_button = tk.Button(
    root,
    text="Generate Map",
    command=generate_map,
    state="disabled",
    width=25,
    height=2,
    bg="#2196F3",
    fg="white"
)
generate_button.pack(pady=10)

# Show Analytics button
analytics_button = tk.Button(
    root,
    text="Show Analytics",
    command=lambda: show_analytics(geo_results, file_path),
    state="disabled",
    width=25,
    height=2,
    bg="#9C27B0",
    fg="white"
)
analytics_button.pack(pady=5)

# Info text
tk.Label(root, text="CSV must have 'Source' and 'Destination' columns.", font=("Arial", 9)).pack(pady=5)

# Status label (for showing “Fetching…” / “Ready”)
status_label = tk.Label(root, text="", font=("Arial", 10), fg="blue")
status_label.pack(pady=5)

root.mainloop()
