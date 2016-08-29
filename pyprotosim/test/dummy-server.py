#!/usr/bin/env python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Test Simulator (simple TCP listener)
# interrupt the program with Ctrl-C

import sys
import SocketServer
import logging

class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)
        return
    BUFFER_SIZE =1024 
    def handle(self):
        # self.request is the TCP socket connected to the client
        while 1:
            dbg="Connection:",self.client_address
            logging.info(dbg)
            #get input ,wait if no data
            data=self.request.recv(self.BUFFER_SIZE)
            #suspect more data (try to get it all without stopping if no data)
            if (len(data)==self.BUFFER_SIZE):
                while 1:
                    try:
                        data+=self.request.recv(self.BUFFER_SIZE, socket.MSG_DONTWAIT)
                    except:
                        #error means no more data
                        break
            #no data found exit loop (posible closed socket)
            if (data != ""): 
                #processing input
                dbg="Incomming message",data.encode("hex")
            else:
                logging.warning("Connection closed")
                break            

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # logging.basicConfig(filename='/path/to/your/log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)
    
    # Define server_host:port to use (empty string means localhost)
    HOST = "192.168.206.1"
    PORT = 8888
    
    # Create the server, binding to HOST:PORT
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

######################################################        
# History
# 0.3.1 - Nov 17, 2012 - initial version

