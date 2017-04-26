#!/usr/bin/python
#importamos el modulo socket
import socket
import os,socket,sys,ssl
import threading
import logging
import time

def conexion(sc,addr):
  while True:
    #Recibimos el mensaje, con el metodo recv recibimos datos y como parametro
    #la cantidad de bytes para recibir
    recibido = sc.recv(2048)
    recibido = sc.recv(2048)
    print recibido
    #Si se reciben datos nos muestra la IP y el mensaje recibido
    #print str(addr[0]) + " dice: ", recibido

    #Devolvemos el mensaje al cliente
    mensaje=str(raw_input(" "))
    print mensaje
    sc.write(mensaje)
    sc.send("\n")
  
   
#instanciamos un objeto para trabajar con el socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
#Con el metodo bind le indicamos que puerto debe escuchar y de que servidor esperar conexiones
#Es mejor dejarlo en blanco para recibir conexiones externas si es nuestro caso
s.bind(("", 9999))
 
#Aceptamos conexiones entrantes con el metodo listen, y ademas aplicamos como parametro
#El numero de conexiones entrantes que vamos a aceptar
s.listen(100)

#Canal  cifrado 
ss=ssl.wrap_socket(s,server_side=True,keyfile="capps.key.pem",certfile="capps.cert.pem",ssl_version=ssl.PROTOCOL_SSLv23)
#Instanciamos un objeto sc (socket cliente) para recibir datos, al recibir datos este 
#devolvera tambien un objeto que representa una tupla con los datos de conexion: IP y puerto
#print sc
threads = list()
while True:
  sc, addr = ss.accept()
  t = threading.Thread(target=conexion, args=(sc,addr))
  threads.append(t)
  t.start()
 
#Cerramos la instancia del socket cliente y servidor
sc.close()
s.close()
