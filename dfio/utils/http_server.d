module utils.http_server;

import utils.http_parser;
import std.socket;
import std.algorithm.mutation : copy;

struct HttpHeader {
	string name, value;
}

struct HttpRequest {
	HttpHeader[] headers;
	const(ubyte)[] uri;
}

struct Index {
	size_t start, end;

	void update(ubyte* base, ubyte[] chunk)
	{
		
	}
}

abstract class SimpleHttpProcessor {
private:
	ubyte[] buffer;
	size_t parsed; // parsed so far
	size_t received; // recieved

	Index[2][] headersBuf; // buffer for headers
	size_t header; // current header
	Index url; // indices for start/end of URL
	bool completed;
	alias Parser = HttpParser!SimpleHttpProcessor;
 	Parser parser;

	final void compact()
	{
		assert(received >= parsed);
		size_t tail = received - parsed;
		if(tail > 0) copy(buffer[parsed..recieved], buffer[0..tail]);
		recieved -= parsed;
		parsed = 0;
	}

package:

	final int onBeginMessage(Parser* parser)
	{
		completed = false;
		return 0;
	}

	final void onHeaderField(Parser* parser, const(ubyte)[] chunk)
	{

	}

	final void onHeaderValue(Parser* parser, const(ubyte)[] chunk)
	{

	}

	final void onCompleteMessage()
	{
		HttpRequest()
	}

public:
	Socket client;

	this(Socket sock) {
		client = sock;
		buffer = new ubyte[1024];
		parser = httpParser!(this, HttpParser.request);
	}

	void run() {
		bool reading = true;
		auto parser = httpParser(SimpleCallbacks(this), HttpParserType);
		scope(exit) {
		    client.shutdown(SocketShutdown.BOTH);
		    client.close();
		}
		while(reading) {
            ptrdiff_t received = client.receive(buffer[used..$]);
            if (received < 0) {
                logf("Error %d", received);
                return;
            }
            else if (received == 0) { //socket is closed (eof)
                reading = false;
            }
            else {
                logf("Server_worker received:\n<%s>", cast(char[])buffer[0.. received]);
                parsed += parser.execute(buffer[parsed..received]);
                if (completed) compact();
            }
        }
	}

	void onStart(HttpRequest req);

	void onBody(const(ubyte)[] chunk);

	void onComplete(HttpRequest req);
}

void serve(Context)(Socket client, Context ctx, void delegate(HttpRequest, Context) onRequest) {
	
    logf("Started server_worker, client = %s", client);
    
    do {
        
        HttpVersion v = parser.protocolVersion();
        // if no connection header present, keep connection for 1.1
        if (connection == 1) keepAlive = true;
        else if (connection < 0 && v.major == 1 && v.minor == 1) keepAlive = true;
        else keepAlive = false;
        logf("Protocol version = %s", v);
        outBuf.clear();
        bodyBuf.clear();
        formattedWrite(bodyBuf, "Hello, world!");
        auto date = Clock.currTime!(ClockType.coarse)(UTC());
        formattedWrite(outBuf,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n",
            bodyBuf.data.length
        );
        writeDate(outBuf, date);
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