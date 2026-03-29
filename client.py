import socket
import threading
import json
from cryptography.fernet import Fernet

key=b'pabmI22uc-Z-GQN6c3nsqYVSLBsoCTI-Xc_OgygMbo0='
cipher=Fernet(key)

SERVER_IP="172.16.141.17"
SERVER_PORT=5100

def recv_exact(conn,n):
    
    buf=b""
    while len(buf)<n:
        chunk=conn.recv(n-len(buf))
        if not chunk:
            return b""
        buf+=chunk
    return buf

def send_msg(conn,plaintext:str):
    encrypted_msg=cipher.encrypt(plaintext.encode())
    length=len(encrypted_msg).to_bytes(4,byteorder='big')
    conn.sendall(length+encrypted_msg)
    
def recv_msg(conn)->str:
    raw_len=recv_exact(conn,4)
    if not raw_len:
        return ""
    msg_len=int.from_bytes(raw_len,byteorder='big')
    data=recv_exact(conn,msg_len)
    if not data:
        return ""
    return cipher.decrypt(data).decode().strip()

def recv_loop(client):
    while True:
        try:
            msg=recv_msg(client)
            
            if not msg:
                print("\n[!] Disconnected from server.")
                break

            if msg.startswith("OK|"):
                print(f"[Server] {msg[3:]}")

            elif msg.startswith("SEND|"):
                print(f"Partner: {msg[5:]}")

            elif msg.startswith("SHOWANS|"):
                users=json.loads(msg[8:])
                print("\n── Online Users ──")
                for user, status in users.items():
                    print(f"  {user}: {status}")
                print("──────────────────")

            elif msg.startswith("REQ|"):
                print(f"\n[Request] {msg[4:]}")
                print("  Reply with ACCEPT|<username> or REJECT|<username>")

            elif msg.startswith("ACCEPT|"):
                print(f"\n[Connected] {msg[7:]}")

            elif msg.startswith("REJECT|"):
                print(f"\n[Rejected] {msg[7:]}")

            elif msg.startswith("ENDCONN|"):
                print(f"\n[Chat ended] {msg[8:]}")

            else:
                print(f"[Server] {msg}")

        except OSError:
            break




client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((SERVER_IP,SERVER_PORT))

recv_thread=threading.Thread(target=recv_loop,args=(client,),daemon=True)
recv_thread.start()

uname=input("Username: ").strip()
send_msg(client,uname)

print("\nCommands:")
print("  SHOW|              -> list online users")
print("  STAT|AVAL or DND   -> change your status")
print("  REQ|<user>         -> request to chat")
print("  ACCEPT|<user>      -> accept a chat request")
print("  REJECT|<user>      -> reject a chat request")
print("  ENDCONN|           -> end current chat")
print("  EXIT|              -> quit")
print("  <anything else>    -> send a message to your partner\n")

while True:
    try:
        msg=input("> ").strip()
    except(EOFError,KeyboardInterrupt):
        send_msg(client,"EXIT|")
        break

    if not msg:
        continue

    if msg.startswith("EXIT|"):
        send_msg(client,msg)
        break
    elif any(msg.startswith(p) for p in ("ENDCONN|","SHOW|","STAT|","REQ|","ACCEPT|","REJECT|")):
        send_msg(client,msg)
    else:
        send_msg(client,"SEND|"+msg)

client.close()
