import std.stdio;
import std.socket;
import dfio;

void main()
{
    ubyte[1024] buffer;
    Socket client = new TcpSocket();
    client.connect(new InternetAddress("localhost", 4444));

    logf("Client connected");
    client.send("GET / HTTP/1.1\r\nCONNECTION: keep-alive\n");
    logf("Client sent data");
    client.receive(buffer);
    logf("Client received data");
    writeln(buffer);
}
