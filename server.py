import socket
import threading
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes

lock=threading.Lock()

private_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
public_key=private_key.public_key()
public_key_bytes=public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


def recv_exact(conn,n):
    buffer=b""
    while len(buffer)<n:
        chunk=conn.recv(n-len(buffer))
        if not chunk:
            return b""
        buffer+=chunk
    return buffer

def send_msg(conn,cipher,plaintext:str):
    encrypted_msg=cipher.encrypt(plaintext.encode())
    encrypted_msg_length=len(encrypted_msg).to_bytes(4,byteorder='big')
    conn.sendall(encrypted_msg_length+encrypted_msg)
    
def recv_msg(conn,cipher)->str:
    raw_len=recv_exact(conn,4)
    if not raw_len:
        return ""
    msg_len=int.from_bytes(raw_len,byteorder='big')
    data=recv_exact(conn,msg_len)
    if not data:
        return ""
    return cipher.decrypt(data).decode().strip()


def get_uname(conn,client_list,status_list):
    
    conn.sendall(len(public_key_bytes).to_bytes(4,byteorder='big'))
    conn.sendall(public_key_bytes)
    
    encrypted_len=int.from_bytes(recv_exact(conn,4),byteorder='big')
    encrypted_fernet_key=recv_exact(conn,encrypted_len)
    
    fernet_key=private_key.decrypt(encrypted_fernet_key,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    
    cipher=Fernet(fernet_key)
    
    uname=recv_msg(conn,cipher)
    with lock:
        client_list[uname]=(conn,cipher)
        status_list[uname]="AVAL"
    send_msg(conn,cipher,f"OK|Welcome {uname}")
    return uname,cipher


def disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=False):
    with lock:
        partner=connection_list.pop(uname,None)
        if partner:
            connection_list.pop(partner,None)
            if notify_partner and partner in status_list:
                status_list[partner]="AVAL"

        if uname in pending_list:
            requester=pending_list.pop(uname)
            if requester in status_list:
                status_list[requester]="AVAL"  

        for target,requester in list(pending_list.items()):
            if requester==uname:
                del pending_list[target]
                break

        client_list.pop(uname,None)
        status_list.pop(uname,None)
        
    if notify_partner and partner:
        try:
            partner_conn,partner_cipher=client_list[partner]
            send_msg(partner_conn,partner_cipher,"ENDCONN|Your partner disconnected.")
        except (KeyError, OSError):
            pass


def master_func(conn,client_list,connection_list,status_list,pending_list):
    uname,cipher=get_uname(conn,client_list,status_list)
    print(f"[SERVER] {uname} connected")

    try:
        while True:
            msg=recv_msg(conn,cipher)

            if not msg:
                disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=True)
                print(f"[SERVER] {uname} disconnected abruptly")
                break

            if msg.startswith("EXIT|"):
                disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=True)
                print(f"[SERVER] {uname} exited")
                break

            elif msg.startswith("ENDCONN|"):
                with lock:
                    partner=connection_list.pop(uname,None)
                    if partner:
                        connection_list.pop(partner,None)
                        status_list[uname]="AVAL"
                        if partner in status_list:
                            status_list[partner]="AVAL"
                if partner and partner in client_list:
                    try:
                        other_client,other_cipher=client_list[partner]
                        send_msg(other_client,other_cipher,"ENDCONN|Your partner ended the chat")
                    except (OSError,KeyError):
                        pass

            elif msg.startswith("SHOW|"):
                with lock:
                    snapshot=dict(status_list)
                send_msg(conn,cipher,"SHOWANS|"+json.dumps(snapshot))

            elif msg.startswith("STAT|"):
                new_status=msg[5:]
                if new_status in ("AVAL","DND"):
                    with lock:
                        status_list[uname]=new_status

            elif msg.startswith("REQ|"):
                other=msg[4:]
                with lock:
                    can_req=(
                        other in client_list
                        and status_list.get(uname)=="AVAL"
                        and status_list.get(other)=="AVAL"
                    )
                    if can_req:
                        pending_list[other]=uname
                        status_list[uname]="PENDING"

                if can_req:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"REQ|{uname} wants to connect. Accept?")
                        send_msg(conn,cipher,f"REQSENT|Request sent to {other}.")
                    except OSError:
                        with lock:
                            status_list[uname]="AVAL"
                            pending_list.pop(other,None)
                    print(f"[SERVER] {uname} sent connection request to {other}")

            elif msg.startswith("ACCEPT|"):
                other=msg[7:]
                with lock:
                    can_accept=(
                        other in client_list
                        and pending_list.get(uname)==other
                        and status_list.get(uname)=="AVAL"
                        and status_list.get(other)=="PENDING"
                    )
                    if can_accept:
                        connection_list[uname]=other
                        connection_list[other]=uname
                        status_list[uname]="BUSY"
                        status_list[other]="BUSY"
                        pending_list.pop(uname,None)

                if can_accept:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"ACCEPT|{uname} accepted your request")
                    except OSError:
                        pass
                    print(f"[SERVER] {uname} and {other} are connected")

            elif msg.startswith("REJECT|"):
                other=msg[7:]
                with lock:
                    can_reject=(
                        other in client_list
                        and pending_list.get(uname)==other
                        and status_list.get(other)=="PENDING"
                    )
                    if can_reject:
                        status_list[other]="AVAL"
                        pending_list.pop(uname,None)

                if can_reject:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"REJECT|{uname} rejected your request")
                    except OSError:
                        pass

            elif msg.startswith("SEND|"):
                with lock:
                    partner=connection_list.get(uname)
                    partner_data=client_list.get(partner) if partner else None
                if partner_data:
                    try:
                        other_client,other_cipher=partner_data
                        send_msg(other_client,other_cipher,msg)
                    except OSError:
                        pass

    finally:
        conn.close()




client_list={}
connection_list={}
status_list={}
pending_list={}

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
server.bind(("0.0.0.0",5100))
server.listen(5)
print("[SERVER] Server listening on port 5100")

while True:
    conn, addr=server.accept()
    print(f"[SERVER] new connection from {addr}")
    t=threading.Thread(
        target=master_func,
        args=(conn, client_list, connection_list, status_list, pending_list),
        daemon=True,
    )
    t.start()
