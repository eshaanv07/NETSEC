import socket
import threading
import json

SERVER_IP="172.16.141.17"
SERVER_PORT=5100


def recv_msg(client):
    while True:
        try:
            msg=client.recv(4096).decode().strip()
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


def send(client,msg):
    try:
        client.sendall(msg.encode())
    except OSError:
        print("[!] Failed to send message.")




client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((SERVER_IP,SERVER_PORT))

recv_thread=threading.Thread(target=recv_msg, args=(client,), daemon=True)
recv_thread.start()

uname=input("Username: ").strip()
send(client,uname)

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
    except (EOFError,KeyboardInterrupt):
        send(client,"EXIT|")
        break

    if not msg:
        continue

    if msg.startswith("EXIT|"):
        send(client,msg)
        break
    elif any(msg.startswith(p) for p in ("ENDCONN|","SHOW|","STAT|","REQ|","ACCEPT|","REJECT|")):
        send(client,msg)
    else:
        send(client,"SEND|" + msg)

client.close()
