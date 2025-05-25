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
    window.geometry("720x550")
    window.configure(bg="#1e1e2f")

    # Title Label
    tk.Label(window, text="🔍 Threat Analytics Dashboard", font=("Segoe UI", 16, "bold"), bg="#1e1e2f", fg="#00FFD1").pack(pady=10)

    # Threat Status Summary
    threat_counts = Counter(item["Threat Status"] for item in data)
    summary_frame = ttk.LabelFrame(window, text="Threat Summary")
    summary_frame.configure(style="Dark.TLabelframe")
    summary_frame.pack(fill="x", padx=15, pady=10)

    for status in ["Clean", "Suspicious", "Malicious", "Unknown"]:
        count = threat_counts.get(status, 0)
        ttk.Label(summary_frame, text=f"{status}: {count}", style="Dark.TLabel").pack(anchor="w", pady=2)

    # Top Malicious IPs Table
    top_malicious = sorted(
        [item for item in data if item["Threat Status"] in ('Malicious', 'Suspicious')],
        key=lambda x: x["Abuse Score"],
        reverse=True
    )[:10]

    table_frame = ttk.LabelFrame(window, text="Top Malicious and Suspicious IPs")
    table_frame.configure(style="Dark.TLabelframe")
    table_frame.pack(fill="both", expand=True, padx=15, pady=5)

    style = ttk.Style()
    style.theme_use("clam")

    style.configure("Treeview",
                    background="#2a2a40",
                    foreground="white",
                    fieldbackground="#2a2a40",
                    rowheight=25,
                    font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background="#3e3e5e", foreground="#00FFD1", font=("Segoe UI", 10, "bold"))
    style.configure("Dark.TLabelframe", background="#1e1e2f", foreground="#00FFD1", font=("Segoe UI", 10, "bold"))
    style.configure("Dark.TLabel", background="#1e1e2f", foreground="white", font=("Segoe UI", 10))

    tree = ttk.Treeview(table_frame, columns=("IP", "Country", "Abuse Score"), show="headings", height=7)
    tree.heading("IP", text="IP")
    tree.heading("Country", text="Country")
    tree.heading("Abuse Score", text="Abuse Score")

    for col in ("IP", "Country", "Abuse Score"):
        tree.column(col, anchor="center", width=150)

    for row in top_malicious:
        tree.insert("", "end", values=(row["IP"], row["Country"], row["Abuse Score"]))
    tree.pack(fill="both", expand=True)

    # Chart Functions
    def show_pie():
        
        window = tk.Toplevel()
        window.title("Threat Distribution Pie Chart")
        window.geometry("720x550")
        window.configure(bg="#1e1e2f")
    
        labels = list(threat_counts.keys())
        sizes = list(threat_counts.values())
        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        plt.title("Threat Distribution")
        plt.tight_layout()
        plt.show()

    def show_bar():
        
        window = tk.Toplevel()
        window.title("Threat Distribution Bar Chart")
        window.geometry("720x550")
        window.configure(bg="#1e1e2f")
        
        labels = list(threat_counts.keys())
        sizes = list(threat_counts.values())
        plt.figure(figsize=(6, 4))
        plt.bar(labels, sizes, color=["green", "orange", "red", "gray"])
        plt.title("Threat Category Count")
        plt.xlabel("Threat Status")
        plt.ylabel("Number of IPs")
        plt.tight_layout()
        plt.show()

    def plot_protocol_distribution():
        
        window = tk.Toplevel()
        window.title("Protocol Traffic Distribution")
        window.geometry("720x550")
        window.configure(bg="#1e1e2f")
        
        if not file_path:
            messagebox.showwarning("File Missing", "No CSV file path provided for protocol analysis.")
            return
        try:
            df = pd.read_csv(file_path)
            if 'Protocol' not in df.columns:
                messagebox.showerror("Error", "'Protocol' column not found in the CSV.")
                return
            protocol_counts = df['Protocol'].value_counts()
            plt.figure(figsize=(7, 5))
            plt.bar(protocol_counts.index, protocol_counts.values, color='#03A9F4')
            plt.title("Protocol Traffic Distribution")
            plt.xlabel("Protocol")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to plot protocol distribution.\n{e}")

    def save_report():
        df = pd.DataFrame(data)
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            df.to_csv(path, index=False)
            messagebox.showinfo("Saved", f"Report saved to {path}")

    # Button Group
    button_frame = tk.Frame(window, bg="#1e1e2f")
    button_frame.pack(pady=15)

    tk.Button(button_frame, text="🧁 Threat Pie Chart", command=show_pie, width=18, height=2, bg="#00b894", fg="black").pack(side="left", padx=8)
    tk.Button(button_frame, text="📊 Threat Bar Chart", command=show_bar, width=18, height=2, bg="#e17055", fg="white").pack(side="left", padx=8)
    tk.Button(button_frame, text="📡 Protocol Chart", command=plot_protocol_distribution, width=18, height=2, bg="#0984e3", fg="white").pack(side="left", padx=8)
    tk.Button(button_frame, text="💾 Save CSV Report", command=save_report, width=18, height=2, bg="#6c5ce7", fg="white").pack(side="left", padx=8)
