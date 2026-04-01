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
    encrypted_msg_length=len(encrypted_msg).to_bytes(4,byteorder='big')
    conn.sendall(encrypted_msg_length+encrypted_msg)
   
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

#returns the username and cipher of fernet key
def get_uname_cipher(conn,client_list,status_list):
    
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
        if uname in client_list:
            send_msg(conn,cipher,"ERROR|Username is already taken")
            conn.close()
            return
        
        client_list[uname]=(conn,cipher)
        status_list[uname]="AVAL"
    send_msg(conn,cipher,f"OK|Welcome {uname}")
    return uname,cipher

#handles a disconnecting user
def disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=False):
    notify_members=[]
    partner=None
    room_name=None
    
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
            
        if uname in user_rooms:
            room_name=user_rooms.pop(uname)
            if room_name in chat_rooms:
                chat_rooms[room_name]["members"].remove(uname)
                
                if not chat_rooms[room_name]["members"]:
                    del chat_rooms[room_name]
                    room_name=None
                    
                else:
                    if chat_rooms[room_name]["owner"]==uname:
                        chat_rooms[room_name]["owner"]=chat_rooms[room_name]["members"][0]
                    notify_members=list(chat_rooms[room_name]["members"])

        client_list.pop(uname,None)
        status_list.pop(uname,None)
        
    if notify_partner and partner:
        try:
            partner_conn,partner_cipher=client_list[partner]
            send_msg(partner_conn,partner_cipher,"ENDCONN|Your partner disconnected.")
        except (KeyError, OSError):
            pass
        
    for member in notify_members:
        try:
            member_conn,member_cipher=client_list[member]
            send_msg(member_conn,member_cipher,f"BROADCAST|{uname} has left the room")
        except (KeyError,OSError):
            pass

#master function
def master_func(conn,client_list,connection_list,status_list,pending_list,chat_rooms,user_rooms):
    uname,cipher=get_uname_cipher(conn,client_list,status_list)
    print(f"[SERVER] {uname} connected")

    try:
        while True:
            msg=recv_msg(conn,cipher)

            #ABRUPT DISCONNECTION FROM SERVER
            if not msg:
                disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=True)
                print(f"[SERVER] {uname} disconnected abruptly")
                break
            
            #PROPER DISCONNECTION FROM SERVER
            if msg.startswith("EXIT|"):
                disconnect_user(uname,client_list,connection_list,status_list,pending_list,notify_partner=True)
                print(f"[SERVER] {uname} exited")
                break
            
            #EXITING CHAT WITH USER
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

            #DISPLAYING ONLINE USERS          
            elif msg.startswith("SHOW|"):
                with lock:
                    snapshot1=dict(status_list)
                    snapshot2=dict(chat_rooms)
                    
                send_msg(conn,cipher,"SHOWANSUSER|"+json.dumps(snapshot1))
                send_msg(conn,cipher,"SHOWANSROOM|"+json.dumps(snapshot2))

            #CHANGING USER STATUS
            elif msg.startswith("STAT|"):
                new_status=msg[5:]
                if new_status in ("AVAL","DND"):
                    with lock:
                        status_list[uname]=new_status
                else:
                    send_msg(conn,cipher,'ERROR|Choose status from "AVAL" or "DND"')

            #REQQUESTING CONNECTION WITH USER
            elif msg.startswith("REQ|"):
                other=msg[4:].strip()
                error=None
                can_req=False
                
                if not other:
                    error="No username specified"
                    
                elif other==uname:
                    error="Cannot chat with yourself"
                    
                else:
                    with lock:
                        if other not in client_list:
                            error="User not online"
                            
                        elif status_list[other]=="DND":
                            error="User set to Do Not Disturb"
                            
                        elif status_list[other]=="BUSY":
                            error="User set to BUSY"
                            
                        elif status_list[other]=="PENDING":
                            error="User has a pending request"
                            
                        elif status_list[uname]!="AVAL":
                            error="You cannot make requests currently"
                        
                        else:
                            pending_list[other]=uname
                            status_list[uname]="PENDING"
                            can_req=True

                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                    
                elif can_req:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"REQ|{uname} wants to connect. Accept?")
                        send_msg(conn,cipher,f"REQSENT|Request sent to {other}.")
                    except (OSError,KeyError):
                        with lock:
                            status_list[uname]="AVAL"
                            pending_list.pop(other,None)
                    print(f"[SERVER] {uname} sent connection request to {other}")

            #ACCEPTING CONNECTION WITH USER
            elif msg.startswith("ACCEPT|"):
                other=msg[7:].strip()
                error=None
                can_accept=False
                
                if not other:
                    error="No username specified"
                    
                elif other==uname:
                    error="Cannot accept yourself"
                    
                else:
                    with lock:
                        if other not in client_list:
                            error="User not online"
                            
                        elif pending_list.get(uname)!=other:
                            error="No pending request from this user"
                            
                        elif status_list[uname]!="AVAL":
                            error="You are not available"
                            
                        elif status_list[other]!="PENDING":
                            error="User is not longer waiting"
                        
                        else:
                            connection_list[uname]=other
                            connection_list[other]=uname
                            status_list[uname]="BUSY"
                            status_list[other]="BUSY"
                            pending_list.pop(uname,None)
                            can_accept=True
                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                elif can_accept:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"ACCEPT|{uname} accepted your request")
                    except (KeyError,OSError):
                        pass
                    print(f"[SERVER] {uname} and {other} are connected")

            #REJECTING CONNECTION WITH USER
            elif msg.startswith("REJECT|"):
                other=msg[7:].strip()
                error=None
                can_reject=False
                
                if not other:
                    error="No username specified"
                    
                elif other==uname:
                    error="Cannot reject yourself"
                    
                else:
                    with lock:
                        if other not in client_list:
                            error="User not online"
                            
                        elif pending_list.get(uname)!=other:
                            error="No pending request from this user"
                            
                        elif status_list[other]!="PENDING":
                            error="User is no longer waiting"
                            
                        else:
                            status_list[other]="AVAL"
                            pending_list.pop(uname,None)
                            can_reject=True
                            
                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                                
                elif can_reject:
                    try:
                        other_client,other_cipher=client_list[other]
                        send_msg(other_client,other_cipher,f"REJECT|{uname} rejected your request")
                    except (KeyError,OSError):
                        pass
                    
            #CREATING ROOM
            elif msg.startswith("CREATEROOM|"):
                room_name=msg[11:].strip()
                error=None
                can_create_room=False
                
                if not room_name:
                    error="Room name not specified"
                    
                else:
                    with lock:
                        if room_name in chat_rooms:
                            error="Room already exists"
                        
                        elif status_list[uname]!="AVAL":
                            error="You cannot create a room currently"
                            
                        else:
                            chat_rooms[room_name]={"owner":uname,"members":[uname]}
                            user_rooms[uname]=room_name
                            status_list[uname]="BUSY"
                            can_create_room=True
                        
                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                    
                elif can_create_room:
                    send_msg(conn,cipher,f"OK|Room:{room_name} created")
                    print(f"[SERVER] {uname} created room {room_name}")
               
            #JOINING ROOM     
            elif msg.startswith("JOINROOM|"):
                room_name=msg[9:].strip()
                error=None
                can_join_room=False
                
                if not room_name:
                    error="Room name not specified"
                    
                else:
                    with lock:
                        if room_name not in chat_rooms:
                            error="Room does not exist"
                        
                        elif status_list[uname]!="AVAL":
                            error="You cannot create a room currently"
                            
                        else:
                            chat_rooms[room_name]["members"].append(uname)
                            user_rooms[uname]=room_name
                            status_list[uname]="BUSY"
                            can_join_room=True
                            
                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                    
                elif can_join_room:
                    send_msg(conn,cipher,f"OK|Joined room {room_name}")
                    
                    with lock:
                        members=list(chat_rooms[room_name]["members"])
                        for member in members:
                            try:
                                member_conn,member_cipher=client_list[member]
                                send_msg(member_conn,member_cipher,f"BROADCAST|{uname} joined the room")
                            except (KeyError,OSError):
                                pass
                                
                        print(f"{uname} joined room {room_name}")
            
            #LEAVING ROOM            
            elif msg.startswith("LEAVEROOM|"):
                error=None
                can_leave_room=False
                
                with lock:
                    if uname not in user_rooms:
                        error=f"{uname} not in a room"
                        
                    else:
                        room_name=user_rooms.pop(uname)
                        chat_rooms[room_name]["members"].remove(uname)
                        status_list[uname]="AVAL"
                        
                        if not chat_rooms[room_name]["members"]:
                            del chat_rooms[room_name]
                            room_name=None
                            
                        elif chat_rooms[room_name]["owner"]==uname:
                            chat_rooms[room_name]["owner"]=chat_rooms[room_name]["members"][0]
                            
                        can_leave_room=True
                        
                if error:
                    send_msg(conn,cipher,f"ERROR|{error}")
                    
                elif can_leave_room:
                    send_msg(conn,cipher,f"OK|You left the room")
                    if room_name:
                        members=list(chat_rooms[room_name]["members"])
                        for member in members:
                            try:
                                member_conn,member_cipher=client_list[member]
                                send_msg(member_conn,member_cipher,f"BROADCAST|{uname} left the room")
                            except (OSError,KeyError):
                                pass
                        print(f"{uname} left room {room_name}")
                            
            #SENDING MESSAGE
            elif msg.startswith("SEND|"):
                with lock:
                    if uname in user_rooms:
                        room_name=user_rooms[uname]
                        members=list(chat_rooms[room_name]["members"])
                        partner=None
                        is_in_room=True
                        
                    else:  
                        partner=connection_list.get(uname)
                        partner_data=client_list.get(partner) if partner else None
                        
                if is_in_room:
                    for member in members:
                        if member!=uname:
                            try:
                                member_conn,member_cipher=client_list[member]
                                send_msg(member_conn,member_cipher,f"BROADCAST|{uname}:{msg[5:]}")
                            except (OSError,KeyError):
                                pass
                            
                elif partner_data:
                    try:
                        partner_conn,partner_cipher=partner_data
                        send_msg(partner_conn,partner_cipher,msg)
                    except (OSError,KeyError):
                        pass

    finally:
        conn.close()


#################################################################################################################


client_list={}
connection_list={}
status_list={}
pending_list={}
chat_rooms={}
user_rooms={}


server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
server.bind(("0.0.0.0",5100))
server.listen(5)
print("[SERVER] Server listening on port 5100")

while True:
    conn, addr=server.accept()
    print(f"[SERVER] new connection from {addr}")
    thread_master_func=threading.Thread(target=master_func,args=(conn, client_list, connection_list,status_list,pending_list,chat_rooms,user_rooms),daemon=True)
    thread_master_func.start()
