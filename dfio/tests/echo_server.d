import std.stdio;
import std.socket;
import std.conv;
import core.thread;
import std.string;
import std.algorithm;
import std.conv;
import std.format;
import std.range;

import dfio;
import http.parser.core;
// curl -d "value=test"  -X POST localhost:1337
// curl -v localhost:1337 -H 'Connection: close'
// curl -v localhost:1337 -H 'Connection: keep-alive'


void server_worker(Socket client) {
    ubyte[1024] buffer;

    scope(exit) {
        client.shutdown(SocketShutdown.BOTH);
        client.close();
    }

    logf("Started server_worker, client = %s", client);
    auto outBuf = appender!(char[]);
    auto bodyBuf = appender!(char[]);
    bool keepAlive = false;
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
        parser.onBody = (parser, HttpBodyChunk data) {
            logf("Parse body, received <%s>", data.buffer);
            formattedWrite(bodyBuf, cast(char[])data.buffer);
        };
        while(reading){
            ptrdiff_t received = client.receive(buffer);
            if (received < 0) {
                logf("Error %d", received);
                perror("Error while reading from client");
                return;
            }
            else if (received == 0) { //socket is closed (eof)
                connection = 0;
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
        else keepAlive = false;
        logf("Protocol version = %s", v);
        outBuf.clear();

        formattedWrite(outBuf,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n",
            bodyBuf.data.length
        );
        if (keepAlive) {
            logf("Keep-alive request");
            formattedWrite(outBuf, "Connection: keep-alive\r\n\r\n");
        }
        else {
            logf("Non keep-alive request");
            formattedWrite(outBuf, "\r\n");
        }
        copy(bodyBuf.data, outBuf);
        logf("Sent <%s>", cast(char[])outBuf.data);
        client.send(outBuf.data);
    } while(keepAlive);
}

void server() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("localhost", 1337));
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

void client(string toSend) {
    auto request = new TcpSocket();
    request.connect(new InternetAddress("localhost", 1337));
    request.send(toSend.dup) ;

    logf("Sending %s", toSend);

    // TODO timeout?
    char[1024] response;
    long len = request.receive(response);
    if (len < 0){
        perror("Error while reading on client");
        abort();
    }

    logf("Received len = %d", len);
    auto received = response[0..len];

    request.close;

    logf("received: %s", received);
}

void main() {
    startloop();
    spawn(() => server());
    runFibers();
}
