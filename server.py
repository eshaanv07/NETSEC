import socket
import threading
import json

lock = threading.Lock()


def get_uname(conn,client_list, status_list):
    uname=conn.recv(4096).decode().strip()
    with lock:
        client_list[uname]=conn
        status_list[uname]="AVAL"
    conn.sendall(f"OK|Welcome {uname}".encode())
    return uname


def disconnect_user(uname,client_list,connection_list,status_list,notify_partner=False):
    with lock:
        partner=connection_list.pop(uname,None)
        if partner:
            connection_list.pop(partner,None)
            if notify_partner and partner in status_list:
                status_list[partner]="AVAL"
        client_list.pop(uname,None)
        status_list.pop(uname,None)

    if notify_partner and partner and partner in client_list:
        try:
            client_list[partner].sendall("ENDCONN|Your partner disconnected.".encode())
        except OSError:
            pass


def master_func(conn,client_list,connection_list,status_list,pending_list):
    uname=get_uname(conn,client_list,status_list)
    print(f"[+] '{uname}' registered")

    try:
        while True:
            rawdata=conn.recv(4096)

            if not rawdata:
                disconnect_user(uname,client_list,connection_list,status_list,notify_partner=True)
                print(f"[-] '{uname}' disconnected abruptly")
                break

            msg = rawdata.decode().strip()

            if msg.startswith("EXIT|"):
                disconnect_user(uname,client_list,connection_list,status_list,notify_partner=True)
                print(f"[-] '{uname}' exited")
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
                        client_list[partner].sendall("ENDCONN|Your partner ended the chat.".encode())
                    except OSError:
                        pass

            elif msg.startswith("SHOW|"):
                with lock:
                    snapshot=dict(status_list)
                conn.sendall(("SHOWANS|" + json.dumps(snapshot)).encode())

            elif msg.startswith("STAT|"):
                new_status=msg[5:]
                if new_status in ("AVAL","DND"):
                    with lock:
                        status_list[uname]=new_status

            elif msg.startswith("REQ|"):
                other = msg[4:]
                with lock:
                    can_req = (
                        other in client_list
                        and status_list.get(uname)=="AVAL"
                        and status_list.get(other)=="AVAL"
                    )
                    if can_req:
                        pending_list[other]=uname
                        status_list[uname]="PENDING"

                if can_req:
                    try:
                        client_list[other].sendall(f"REQ|{uname} wants to connect. Accept?".encode())
                    except OSError:
                        with lock:
                            status_list[uname]="AVAL"
                            pending_list.pop(other,None)
                    print(f"[~] '{uname}' sent connection request to '{other}'")

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
                        client_list[other].sendall(f"ACCEPT|{uname} accepted your request".encode())
                    except OSError:
                        pass
                    print(f"[+] '{uname}' and '{other}' are now connected")

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
                        client_list[other].sendall(f"REJECT|{uname} rejected your request.".encode())
                    except OSError:
                        pass

            elif msg.startswith("SEND|"):
                with lock:
                    partner=connection_list.get(uname)
                    partner_sock=client_list.get(partner) if partner else None
                if partner_sock:
                    try:
                        partner_sock.sendall(msg.encode())
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
print("Server listening on port 5100")

while True:
    conn, addr=server.accept()
    print(f"[+] New connection from {addr}")
    t=threading.Thread(
        target=master_func,
        args=(conn, client_list, connection_list, status_list, pending_list),
        daemon=True,
    )
    t.start()
