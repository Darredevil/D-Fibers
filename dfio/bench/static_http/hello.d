import std.algorithm;
import std.conv;
import std.datetime;
import std.format;
import std.range;
import std.stdio;
import std.string;
import std.socket;
import std.uni;
import core.thread;

import dfio;
import utils.http_server;

class HelloWorldProcessor : HttpProcessor {
    this(Socket sock){ super(sock); }
    
    override void onComplete(HttpRequest req) {
        respondWith("Hello, world!", 200);
    }
}

void server_worker(Socket client) {
    scope processor =  new HelloWorldProcessor(client);
    processor.run();
}

void server() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("0.0.0.0", 8080));
    server.listen(1000);

    logf("Started server");

    void processClient(Socket client) {
        spawn(() => server_worker(client));
    }

    while(true) {
        try {
            logf("Waiting for server.accept()");
            Socket client = server.accept();
            logf("New client accepted %s", client);
            processClient(client);
        }
        catch(Exception e) {
            writefln("Failure to accept %s", e);
        }
    }
}

void main() {
    version(Windows) {
        import core.memory;
        GC.disable(); // temporary for Win64 UMS threading
    }
    startloop();
    spawn(() => server());
    runFibers();
}
