import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from collections import Counter
import pandas as pd

def show_analytics(data, file_path=None):
    if not data:
        messagebox.showinfo("No Data", "No geolocation data available.")
        return

    window = tk.Toplevel()
    window.title("Analytics Dashboard")
    window.geometry("700x520")

    # Threat Status Summary
    threat_counts = Counter(item["Threat Status"] for item in data)
    summary_frame = ttk.LabelFrame(window, text="Threat Summary", padding=10)
    summary_frame.pack(fill="x", padx=10, pady=10)

    for status in ["Clean", "Suspicious", "Malicious", "Unknown"]:
        count = threat_counts.get(status, 0)
        ttk.Label(summary_frame, text=f"{status}: {count}", font=("Arial", 10)).pack(anchor="w")

    # Top Malicious IPs
    top_malicious = sorted(
        [item for item in data if item["Threat Status"] in ('Malicious', 'Suspicious')],
        key=lambda x: x["Abuse Score"],
        reverse=True
    )[:10]

    table_frame = ttk.LabelFrame(window, text="Top Malicious and Suspicious IPs", padding=10)
    table_frame.pack(fill="both", expand=True, padx=10, pady=5)

    tree = ttk.Treeview(table_frame, columns=("IP", "Country", "Abuse Score"), show="headings")
    tree.heading("IP", text="IP")
    tree.heading("Country", text="Country")
    tree.heading("Abuse Score", text="Abuse Score")
    for row in top_malicious:
        tree.insert("", "end", values=(row["IP"], row["Country"], row["Abuse Score"]))
    tree.pack(fill="both", expand=True)

    # Threat Pie Chart
    def show_pie():
        labels = list(threat_counts.keys())
        sizes = list(threat_counts.values())
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        plt.title("Threat Distribution")
        plt.show()

    # Threat Bar Chart
    def show_bar():
        labels = list(threat_counts.keys())
        sizes = list(threat_counts.values())
        plt.figure(figsize=(6, 4))
        plt.bar(labels, sizes, color=["green", "orange", "red", "gray"])
        plt.title("Threat Category Count")
        plt.xlabel("Threat Status")
        plt.ylabel("Number of IPs")
        plt.show()

    # Protocol Pie Chart
    def plot_protocol_distribution():
        if not file_path:
            messagebox.showwarning("File Missing", "No CSV file path provided for protocol analysis.")
            return
        try:
            df = pd.read_csv(file_path)
            if 'Protocol' not in df.columns:
                messagebox.showerror("Error", "'Protocol' column not found in the CSV.")
                return
            protocol_counts = df['Protocol'].value_counts()
            plt.figure(figsize=(7, 7))
            plt.bar(protocol_counts.index, protocol_counts.values, color='skyblue')
            plt.title("Protocol Traffic Distribution")
            plt.xlabel("Protocol")
            plt.ylabel("Number of IPs")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to plot protocol distribution.\n{e}")

    # Export Button
    def save_report():
        df = pd.DataFrame(data)
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            df.to_csv(path, index=False)
            messagebox.showinfo("Saved", f"Report saved to {path}")

    # Buttons
    button_frame = tk.Frame(window)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Show Pie Chart", command=show_pie, width=16, bg="#03A9F4", fg="white").pack(side="left", padx=5)
    tk.Button(button_frame, text="Show Bar Chart", command=show_bar, width=16, bg="#FF9800", fg="white").pack(side="left", padx=5)
    tk.Button(button_frame, text="Protocol Pie Chart", command=plot_protocol_distribution, width=18, bg="#607D8B", fg="white").pack(side="left", padx=5)
    tk.Button(button_frame, text="Save CSV Report", command=save_report, width=18, bg="#4CAF50", fg="white").pack(side="left", padx=5)
