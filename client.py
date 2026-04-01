import socket
import threading
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
    
SERVER_IP="172.16.141.17"
SERVER_PORT=5100

#receives exact n bytes from conn----data received is encrypted
def recv_exact(conn,n):
    buffer=b""
    while len(buffer)<n:
        chunk=conn.recv(n-len(buffer))
        if not chunk:
            return b""
        buffer+=chunk
    return buffer

#sends encrypted string----data is encrypted in func
def send_msg(conn,cipher,plaintext:str):
    encrypted_msg=cipher.encrypt(plaintext.encode())
    length=len(encrypted_msg).to_bytes(4,byteorder='big')
    conn.sendall(length+encrypted_msg)
    
#receives string----data is decrypted in func     
def recv_msg(conn,cipher)->str:
    raw_len=recv_exact(conn,4)
    if not raw_len:
        return ""
    msg_len=int.from_bytes(raw_len,byteorder='big')
    data=recv_exact(conn,msg_len)
    if not data:
        return ""
    return cipher.decrypt(data).decode().strip()
    
#exchnages fernet key with server   
def perform_handshake(client):
    
    key_len=int.from_bytes(recv_exact(client,4),byteorder='big')
    public_key_bytes=recv_exact(client,key_len)
    public_key=load_pem_public_key(public_key_bytes)
    
    fernet_key=Fernet.generate_key()
    cipher=Fernet(fernet_key)
    
    encrypted_fernet_key=public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    client.sendall(len(encrypted_fernet_key).to_bytes(4,byteorder='big'))
    client.sendall(encrypted_fernet_key)
    
    return cipher

#handle proper printing of >
def print_msg(msg: str):
    print(f"\r{msg}")
    print("\r> ",end="",flush=True)

#main data receiving loop
def recv_loop(client,cipher):
    while True:
        try:
            msg=recv_msg(client,cipher)
            
            if not msg:
                print_msg("[DISCONNECTED] Disconnected from server\n")
                break

            if msg.startswith("OK|"):
                print_msg(f"[SERVER] {msg[3:]}")

            elif msg.startswith("SEND|"):
                print_msg(f"Partner: {msg[5:]}")

            elif msg.startswith("SHOWANSUSER|"):
                users=json.loads(msg[12:])
                print("\nOnline Users:")
                for user,status in users.items():
                    print(f"{user} : {status}")
                print("──────────────────")
                
            elif msg.startswith("SHOWANSROOM|"):
                rooms=json.loads(msg[12:])
                if not rooms:
                    print_msg("No active rooms")
                else:
                    print("\rActive Rooms:")
                    for room_name,room_data in rooms.items():
                        print(f"{room_name} | Owner: {room_data['owner']} | Members: {', '.join(room_data['members'])}")
                    print("──────────────────")
                    print("\r> ", end="", flush=True)

            elif msg.startswith("REQ|"):
                print_msg(f"[Request] {msg[4:]}\n")
                print_msg("Reply-->ACCEPT|<username> or REJECT|<username>")
                
            elif msg.startswith("REQSENT|"):
                print_msg(f"[SERVER] {msg[8:]}\n")

            elif msg.startswith("ACCEPT|"):
                print_msg(f"[CONNECTED] {msg[7:]}\n")

            elif msg.startswith("REJECT|"):
                print_msg(f"[REJECTED] {msg[7:]}\n")

            elif msg.startswith("ENDCONN|"):
                print_msg(f"[CHAT ENDED] {msg[8:]}\n")
                
            elif msg.startswith("ERROR|"):
                print_msg(f"[ERROR] {msg[6:]}\n")
                
            elif msg.startswith("BROADCAST|"):
                print_msg(f"[BROADCAST] {msg[10:]}")

            else:
                print_msg(f"[DEBUG] {msg}")

        except OSError:
            break


##########################################################################################################


client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((SERVER_IP,SERVER_PORT))

cipher=perform_handshake(client)

recv_thread=threading.Thread(target=recv_loop,args=(client,cipher),daemon=True)
recv_thread.start()

uname=input("Username: ").strip()
send_msg(client,cipher,uname)

print("\nCommands:")
print("SHOW|              -> list online users")
print("STAT|AVAL or DND   -> change your status to AVAL or DND")
print("REQ|<user>         -> request to chat")
print("ACCEPT|<user>      -> accept a chat request")
print("REJECT|<user>      -> reject a chat request")
print("ENDCONN|           -> end current chat")
print("EXIT|              -> quit")
print("<anything else>    -> send a message to your partner\n")

while True:
    try:
        msg=input("> ").strip()
    except(EOFError,KeyboardInterrupt):
        send_msg(client,cipher,"EXIT|")
        break

    if not msg:
        continue

    if msg.startswith("EXIT|"):
        send_msg(client,cipher,msg)
        break
    elif any(msg.startswith(p) for p in ("ENDCONN|","SHOW|","STAT|","REQ|","ACCEPT|","REJECT|","BROADCAST|","CREATEROOM|","JOINROOM|","LEAVEROOM|")):
        send_msg(client,cipher,msg)
    else:
        send_msg(client,cipher,"SEND|"+msg)

client.close()
