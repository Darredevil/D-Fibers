import std.stdio;
import std.socket;
import std.conv;
import core.thread;
import std.string;

import dfio;
// curl -d "value=test"  -X POST localhost:1337


void server() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("localhost", 1337));
    server.listen(1);

    while(true) {
        Socket client = server.accept();

        char[1024] buffer;
        auto received = client.receive(buffer);

        logf("Server received:\n%s", buffer[0.. received]);

        enum header =
            "HTTP/1.0 200 OK\nContent-Type: text/html; charset=utf-8\n\n";

        string response = header ~ to!string(buffer[0..received]) ~ "\n";
        client.send(response);

        client.shutdown(SocketShutdown.BOTH);
        client.close();
    }
}

void client(string toSend) {
    auto request = new TcpSocket();
    request.connect(new InternetAddress("localhost", 1337));
    request.send(toSend.dup) ;

    // TODO timeout?
    char[1024] response;
    size_t len = request.receive(response);
    auto received = response[0..len];

    request.close;

    logf("received: %s", received);
}

void main() {

    startloop();

    auto wr = new Thread(() => server());
    wr.start();

    Thread.sleep( dur!("seconds")( 1 ) );
    spawn(() => client("client 1\n"));
    spawn(() => client("client 2\n"));
    spawn(() => client("client 3\n"));
    spawn(() => client("client 4\n"));


    runUntilCompletion();
    wr.join();
}
