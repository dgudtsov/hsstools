#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1, Last change on Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# SMPP Simulator build upon libSmpp
# interrupt the program with Ctrl-C

#Next two lines include parent directory for where libSmpp is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import SocketServer
from libSmpp import *

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
                logging.info(dbg)
                ret=process_request(data.encode("hex")) 
                if ret==ERROR:
                    dbg="Error responding",ret
                    logging.error(dbg)
                    break
                else:
                    dbg="Sending response",ret
                    logging.info(dbg)
                    self.request.send(ret.decode("hex"))
            else:
                logging.warning("Connection closed")
                break            

def process_request(rawdata):
    H=HDRItem()
    stripHdr(H,rawdata)
    if H.operation=='00000002':
        logging.info("bind_transmitter")
        return create_bind_transmitter_res(H)
    if H.operation=='00000004':
        logging.info("submit_sm")
        return create_submit_sm_res(H)        
    if H.operation=='00000006':
        logging.info("unbind")
        return create_unbind_res(H)  
    return ERROR
    
def create_bind_transmitter_res(H):
    R=HDRItem()
    R.mandatory.append('system_id=1')
    R.sequence=H.sequence
    R.result=0 #OK
    R.operation='80000002'
    return packHdr(R)

def create_submit_sm_res(H):
    R=HDRItem()
    R.mandatory.append('message_id=123')
    R.sequence=H.sequence
    R.result=0 #OK
    R.operation='80000004'
    return packHdr(R)    

def create_unbind_res(H):
    R=HDRItem()
    R.sequence=H.sequence
    R.result=0 #OK
    R.operation='80000006'
    return packHdr(R) 
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # logging.basicConfig(filename='/path/to/your/log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)
    
    # Define server_host:port to use (empty string means localhost)
    HOST = ""
    PORT = 8889
    
    LoadDictionary("../dictSMPP.xml")
    # Create the server, binding to HOST:PORT
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

######################################################        
# History
# 0.3.1 - Nov 17, 2012 - initial version

