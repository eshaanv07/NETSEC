import socket
import threading
import json

def recv_msg(client):
    while True:
        try:
            msg=client.recv(4096).decode()
            if msg.startswith("SEND|"):
                print("partner:",msg[5:])
                
            elif msg.startswith("SHOWANS|"):
                msg=msg[8:]
                reqdata=json.loads(msg)
                print(reqdata)
                
            elif msg.startswith("REQ|"):
                print(msg[4:])
        except:
            break
        
client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect(('172.16.141.17',5100))

t2=threading.Thread(target=recv_msg,args=(client,),daemon=True)
t2.start() 

uname=input("Username:")
client.send(uname.encode())

while True:
    msg=input(">")
    
    if msg.startswith("EXIT|"):
        client.send(msg.encode())
        break
    
    elif msg.startswith("ENDCONN|"):
            client.send(msg.encode())
            
    elif msg.startswith("CONN|"):
        client.send(msg.encode()) 
        
    elif msg.startswith("SHOW|"):
        client.send(msg.encode())
        
    elif msg.startswith("STAT|"):
        client.send(msg.encode())
        
    elif msg.startswith("REQ|"):
        client.send(msg.encode())
        
    elif msg.startswith("ACCEPT|"):
        client.send(msg.encode())
        
    elif msg.startswith("REJECT|"):
        client.send(msg.encode())
        
    else:
        client.send(("SEND|"+msg).encode())
client.close()

    
     