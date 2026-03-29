import socket
import threading
import json

def master_func(conn,client_list,connection_list,status_list,pending_list):
    
    uname=get_uname(conn,client_list,status_list)
    
    while True:
        rawdata=conn.recv(4096)
        
        if not rawdata:
            if uname in connection_list:
                otheruname=connection_list[uname]
                del connection_list[uname]
                del connection_list[otheruname]
                status_list[otheruname] = "AVAL"
            del client_list[uname]
            del status_list[uname]
            break
        
        msg=rawdata.decode().strip()
        
        if msg.startswith("EXIT|"):
            if uname in connection_list:
                otheruname=connection_list[uname]
                del connection_list[uname]
                del connection_list[otheruname]
                status_list[otheruname]="AVAL"
                
            del client_list[uname]
            del status_list[uname]
            break
        
        elif msg.startswith("ENDCONN|"):
            if uname in connection_list:
                otheruname=connection_list[uname]

                del connection_list[uname]
                del connection_list[otheruname]
                status_list[uname]="AVAL"
                status_list[otheruname]="AVAL"
                
        elif msg.startswith("SHOW|"):
            msg="SHOWANS|"+json.dumps(status_list)
            conn.sendall(msg.encode())

        elif msg.startswith("STAT|"):
            msg=msg[5:]
            if msg=="AVAL" or msg=="DND":
                status_list[uname]=msg
                
        elif msg.startswith("REQ|"):
            otheruname=msg[4:]
            if otheruname in client_list and status_list[uname]=="AVAL" and status_list[otheruname]=="AVAL":
                pending_list[uname]=otheruname
                status_list[uname]="PENDING"
                partner_socket=client_list[otheruname]
                partner_socket.sendall(("REQ|Do you accept connection with "+uname).encode())
                print(uname,"has pending connection request with",otheruname)
                
        elif msg.startswith("ACCEPT|"):
            otheruname=msg[7:]
            if otheruname in client_list and otheruname in pending_list and status_list[uname]=="AVAL" and status_list[otheruname]=="PENDING":
                connection_list[uname]=otheruname
                connection_list[otheruname]=uname
                status_list[uname]="BUSY"
                status_list[otheruname]="BUSY"
                print(uname,"connected with",otheruname)
                del pending_list[otheruname]
                
        elif msg.startswith("REJECT|"):
            otheruname=msg[7:]
            if otheruname in client_list and otheruname in pending_list and status_list[uname]=="AVAL" and status_list[otheruname]=="PENDING":
                status_list[otheruname]="AVAL"
                del pending_list[otheruname]
            
            
        elif msg.startswith("SEND|"):
            
            if uname in connection_list:
                otheruname=connection_list[uname]
                if otheruname in client_list:
                    partner_socket=client_list[otheruname]
                    partner_socket.sendall(msg.encode())
    conn.close()
                
    

def get_uname(conn,client_list,status_list):
    uname=conn.recv(4096).decode().strip()
    client_list[uname]=conn
    status_list[uname]="AVAL"
    return uname

                
    
client_list={}
connection_list={}
status_list={}
pending_list={}

server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(('0.0.0.0',5100))
server.listen(5)
print("Server listening on port 5100")

while True:
    conn,addr=server.accept()
    print("New client connected: ",addr)
    
    t1=threading.Thread(target=master_func,args=(conn,client_list,connection_list,status_list,pending_list))
    t1.start()

    
