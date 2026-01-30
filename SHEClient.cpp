// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ext/stdiobuf.h>
#include <SHEConnect.h>

std::iostream *SHEConnect(int port, char *host)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return NULL;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, host, &serv_addr.sin_addr)<=0) {
        return NULL;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        return NULL;
    }
    __gnu_cxx::stdio_filebuf<char> filebuf(socket, std::ios::in|std::ios::out);
    return new iostream(filebuf);
}

