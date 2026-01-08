import joblib
import pandas as pd
import time
from collections import Counter
from scapy.all import sniff, ARP
import threading
import tkinter as tk
from tkinter import ttk
import winsound


# ================= MODEL =================
model = joblib.load("arp_spoofing_model.pkl")

FEATURE_COLUMNS = [
    'ARP_Req_Count',
    'ARP_Rep_Count',
    'ARP_Ratio',
    'ARP_Rate',
    'ARP_Avg_IAT',
    'Max_MAC_Freq',
    'Unique_IPs'
]

WINDOW_TIME = 5  # seconds
running = False

# ================= GUI =================
root = tk.Tk()
root.title("ARP Spoofing Detection System")
root.geometry("550x500")
root.resizable(False, False)

status_label = tk.Label(
    root, text="Status: Idle",
    font=("Arial", 14), fg="blue"
)
status_label.pack(pady=10)

result_label = tk.Label(
    root, text="Waiting...",
    font=("Arial", 20, "bold")
)
result_label.pack(pady=10)

tree = ttk.Treeview(root, columns=("value"), show="headings")
tree.heading("value", text="Value")
tree.pack(pady=10, fill="x")

for col in FEATURE_COLUMNS:
    tree.insert("", "end", iid=col, values=("0",))
    tree.item(col, text=col)

# ================= DETECTION FUNCTION =================
def start_detection():
    global running
    running = True
    status_label.config(text="Status: Monitoring...", fg="green")

    while running:
        arp_packets = []
        timestamps = []
        mac_addresses = []
        ip_addresses = []

        def capture_arp(packet):
            if packet.haslayer(ARP):
                arp_packets.append(packet)
                timestamps.append(time.time())
                mac_addresses.append(packet[ARP].hwsrc)
                ip_addresses.append(packet[ARP].psrc)

        sniff(filter="arp", prn=capture_arp, timeout=WINDOW_TIME)

        # ========== FEATURES ==========
        ARP_Req_Count = sum(1 for p in arp_packets if p[ARP].op == 1)
        ARP_Rep_Count = sum(1 for p in arp_packets if p[ARP].op == 2)
        ARP_Ratio = ARP_Req_Count / ARP_Rep_Count if ARP_Rep_Count != 0 else 0
        ARP_Rate = len(arp_packets) / WINDOW_TIME

        if len(timestamps) > 1:
            iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            ARP_Avg_IAT = sum(iats) / len(iats)
        else:
            ARP_Avg_IAT = 0

        mac_counter = Counter(mac_addresses)
        Max_MAC_Freq = max(mac_counter.values()) if mac_counter else 0
        Unique_IPs = len(set(ip_addresses))

        data = pd.DataFrame([[
            ARP_Req_Count,
            ARP_Rep_Count,
            ARP_Ratio,
            ARP_Rate,
            ARP_Avg_IAT,
            Max_MAC_Freq,
            Unique_IPs
        ]], columns=FEATURE_COLUMNS)

        # ========== PREDICTION ==========
        prediction = model.predict(data)[0]

        # ========== UPDATE GUI ==========
        values = [
            ARP_Req_Count, ARP_Rep_Count, f"{ARP_Ratio:.2f}",
            f"{ARP_Rate:.2f}", f"{ARP_Avg_IAT:.4f}",
            Max_MAC_Freq, Unique_IPs
        ]

        for col, val in zip(FEATURE_COLUMNS, values):
            tree.item(col, values=(val,))
        global alarm_active
        if prediction == 1:
            result_label.config(
                text="⚠ ATTACK DETECTED ⚠",
                fg="red"
            )
            if not alarm_active:
                winsound.PlaySound("alarm.wav", winsound.SND_FILENAME | winsound.SND_ASYNC)
                alarm_active = True
        else:
            result_label.config(
                text="✔ NORMAL TRAFFIC",
                fg="green"
            )
            alarm_active = False

# ================= BUTTONS =================
def run_thread():
    t = threading.Thread(target=start_detection, daemon=True)
    t.start()

start_btn = tk.Button(
    root, text="Start Detection",
    command=run_thread,
    bg="green", fg="white", font=("Arial", 12)
)
start_btn.pack(pady=10)

stop_btn = tk.Button(
    root, text="Stop",
    command=lambda: stop_detection(),
    bg="red", fg="white", font=("Arial", 12)
)
stop_btn.pack(pady=5)

def stop_detection():
    global running
    running = False
    status_label.config(text="Status: Stopped", fg="red")

root.mainloop()

