import std.algorithm;
import std.conv;
import std.format;
import std.range;
import std.stdio;
import std.string;
import std.socket;
import core.thread;

import dfio;
import http.parser.core;

void server_worker(Socket client) {
    ubyte[1024] buffer;
    
    scope(exit) {
        client.shutdown(SocketShutdown.BOTH);
        client.close();
    }
    auto outBuf = appender!(char[]);
    auto bodyBuf = appender!(char[]);
    bool keepAlive = false;
    logf("Started server_worker, client = %s", client);
    
    do {
        scope parser = new HttpParser();    
        bool reading = true;
        int connection = -1;
        bodyBuf.clear();
        parser.onMessageComplete = (parser) {
            reading = false;
        };
        parser.onHeader = (parser, HttpHeader header) {
            logf("Parser Header <%s> with value <%s>", header.name, header.value);
            if (header.name.toLower == "connection")
                if (header.value.toLower == "close")
                    connection = 0;
                else 
                    connection = 1;
        };
        while(reading){            
            ptrdiff_t received = client.receive(buffer);
            if (received < 0) {
                logf("Error %d", received);
                perror("Error while reading from client");
                return;
            }
            else if (received == 0) { //socket is closed (eof)
                keepAlive = false;
                reading = false;
            }
            else {
                logf("Server_worker received:\n<%s>", cast(char[])buffer[0.. received]);
                parser.execute(buffer[0..received]);
            }
        }
        HttpVersion v = parser.protocolVersion();
        // if no connection header present, keep connection for 1.1
        if (connection == 1) keepAlive = true;
        else if (connection < 0 && v.major == 1 && v.minor == 1) keepAlive = true;
        logf("Protocol version = %s", v);
        outBuf.clear();
        bodyBuf.clear();
        formattedWrite(bodyBuf, "Hello, world!");
        if (keepAlive) {
            logf("Keep-alive request");
            formattedWrite(outBuf, 
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n",
                bodyBuf.data.length);        
        }
        else {
            logf("Non keep-alive request");
            formattedWrite(outBuf, 
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n",
                bodyBuf.data.length);
        }
        copy(bodyBuf.data, outBuf);
        logf("Sent <%s>", cast(char[])outBuf.data);
        client.send(outBuf.data);
    } while(keepAlive);
}

void server() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("localhost", 8080));
    server.listen(1000);

    logf("Started server");

    void processClient(Socket client) {
        spawn(() => server_worker(client));
    }

    while(true) {
        logf("Waiting for server.accept()");
        Socket client = server.accept();
        logf("New client accepted %s", client);
        processClient(client);
    }
}

void main() {
    startloop();
    spawn(() => server());
    runFibers();
}
