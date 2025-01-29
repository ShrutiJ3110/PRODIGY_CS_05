import tkinter as tk
from scapy.all import *
import threading

# Global variable to control sniffing
sniffing = False

# Function to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet.proto
        payload = str(packet.payload)[:50]

        packet_info = f"Source IP: {source_ip}\nDestination IP: {dest_ip}\nProtocol: {protocol}\nPayload: {payload}\n{'-' * 50}"
        display_packet(packet_info)

# Display packet information in the text box
def display_packet(packet_info):
    text_box.insert(tk.END, packet_info + "\n\n")
    text_box.yview(tk.END)

# Start sniffing packets in a separate thread
def start_sniffing():
    global sniffing
    sniffing = True
    filter_choice = filter_var.get()

    try:
        sniff(
            filter="" if filter_choice == "all" else filter_choice,
            prn=packet_callback,
            store=0,
            stop_filter=lambda x: not sniffing
        )
    except scapy.error.Scapy_Exception as e:
        display_packet(f"Error: {str(e)}. Please check filter or permissions.")
        stop_sniffing()

# Stop sniffing packets
def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing stopped.", fg="red")

# Start sniffing in a new thread
def start_sniffing_thread():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()
    status_label.config(text="Sniffing in progress...", fg="green")

# GUI setup
root = tk.Tk()
root.title("Enhanced Network Packet Analyzer")
root.geometry("700x600")

# Configure grid for a responsive layout
root.rowconfigure(1, weight=1)
root.columnconfigure(0, weight=1)

# Disclaimer Label
disclaimer_label = tk.Label(
    root,
    text="Disclaimer: This tool is for educational purposes only. Unauthorized use may violate privacy laws.",
    wraplength=650,
    fg="darkred"
)
disclaimer_label.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

# Text Box to Display Packet Info
text_box = tk.Text(root, wrap=tk.WORD)
text_box.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

# Status Label
status_label = tk.Label(root, text="Ready to sniff packets.", fg="blue")
status_label.grid(row=2, column=0, pady=5, sticky="w")

# Frame for Filter Selection
filter_frame = tk.Frame(root)
filter_frame.grid(row=3, column=0, padx=10, pady=10, sticky="w")

filter_label = tk.Label(filter_frame, text="Select Packet Filter:")
filter_label.pack(side=tk.LEFT, padx=5)
filter_var = tk.StringVar(value="all")

# Packet Filter Options
filters = ["all", "ip", "tcp", "udp", "icmp"]
for f in filters:
    tk.Radiobutton(filter_frame, text=f.upper(), variable=filter_var, value=f).pack(side=tk.LEFT, padx=5)

# Buttons for Start and Stop
button_frame = tk.Frame(root)
button_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing_thread, bg="lightgreen")
stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="salmon")

start_button.pack(side=tk.LEFT, padx=10)
stop_button.pack(side=tk.LEFT, padx=10)

# Expand widgets when maximizing
text_box.pack_propagate(False)

# Start the GUI event loop
root.mainloop()
