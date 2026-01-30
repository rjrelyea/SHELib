#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <SHEServer.h>
#include <pthread.h>

int SHEServer(int port, SHERequestFP handleRequest)
{
    int serverFd, newSsocket, valread;
    struct sockaddrIn address;
    int opt = 1;
    int addrlen = sizeof(address);
    pthread_attr_t attr;

    // set up threads as detached threads
    if (pthread_attr_init(&attr) < 0) {
      return -1;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) < 0) {
      return -1;
    }
    // Creating socket file descriptor
    if ((serverFd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        return -1;
    }
    
    if (setsockopt(serverFd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        return -1;    
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
    
    // attach the socket to the port
    if (bind(serverFd, (struct sockaddr *)&address, sizeof(address))<0) {
        return -1;
    }
    do {
        pthread_t threadID;
        if (listen(serverFd, 3) < 0) {
            return -1;
        }
        if ((newSocket = accept(serverFd, (struct sockaddr *)&address,
                                (socklen_t*)&addrlen))<0) {
            return -1;
        }
        // import socket into a c++ stream
        __gnu_cxx::stdio_filebuf<char> clientSock(newSocket, 
                                                  std::ios::in|std::ios::out);
        istream cs(&clientSocket);
        // launch detached thread to handle client request
        pthread_create(&threadID, &attr, handleRequest, new istream(clientSocket);
    }   while (1);
    // not reached
}
