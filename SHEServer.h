#include <iostream>
// callback function to handle a server request. funtion inherits the stream
// pointer and is responsible for freeing it. Each request will be on it's
// own thread.
typedef (*SHERequestFP)( std::iostream *str );

// handle the boiler plate of a simple socket server.
// Port is the point to bind to, handleRequest is
// a call back. Call backs happen on their own threads.
// This function only returns on an error.
int SHEServer(int port, SHERequestFP handleRequest);
