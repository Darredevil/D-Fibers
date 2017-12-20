import std.stdio;
import std.socket;
import std.conv;
import std.string;

// curl -d "value=test"  -X POST localhost:1337


void main() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("localhost", 1337));
    server.listen(1);

    while(true) {
        Socket client = server.accept();

        char[1024] buffer;
        auto received = client.receive(buffer);

        writefln("The client said:\n%s", buffer[0.. received]);

        enum header =
            "HTTP/1.0 200 OK\nContent-Type: text/html; charset=utf-8\n\n";

        string response = header ~ to!string(buffer[0..received]) ~ "\n";
        client.send(response);

        client.shutdown(SocketShutdown.BOTH);
        client.close();
    }
}
