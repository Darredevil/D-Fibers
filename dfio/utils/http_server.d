/// An example "HTTP server" with poor usability but sensible performance
///
module utils.http_server;
import std.array, std.datetime, std.exception, std.format, std.algorithm.mutation, std.socket;
import core.stdc.stdlib;
import utils.http_parser;

struct HttpHeader {
	const(char)[] name, value;
}

struct HttpRequest {
	HttpHeader[] headers;
	HttpMethod method;
	const(char)[] uri;
}

abstract class HttpProcessor {
private:
	enum State { url, field, value, done };
	ubyte[] buffer;
	Appender!(char[]) outBuf;
	HttpHeader[] headers; // buffer for headers
	size_t header; // current header
	const(char)[] url; // url
	alias Parser = HttpParser!HttpProcessor;
 	Parser parser;
 	ScratchPad pad;
 	HttpRequest request;
 	State state;
 	bool serving;
public:
	Socket client;

	this(Socket sock) {
		serving = true;
		client = sock;
		buffer = new ubyte[2048];
		headers = new HttpHeader[1];
		pad = ScratchPad(16*1024);
		parser = httpParser(this, HttpParserType.request);
	}

	void run() {
		scope(exit) {
		    client.shutdown(SocketShutdown.BOTH);
		    client.close();
		}
		while(serving) {
            ptrdiff_t received = client.receive(buffer);
            if (received < 0) {
                return;
            }
            else if (received == 0) { //socket is closed (eof)
                serving = false;
            }
            else {
            	//TODO: may not parse all of input but that should be an error
                parser.execute(buffer[0..received]);
            }
        }
	}

	void respondWith(const(char)[] _body, uint status, HttpHeader[] headers...)
	{
		return respondWith(cast(const(ubyte)[])_body, status, headers);
	}

	void respondWith(const(ubyte)[] _body, uint status, HttpHeader[] headers...)
	{
		formattedWrite(outBuf,
            "HTTP/1.1 %s OK\r\n", status
        );
        outBuf.put("Server: photon/simple\r\n");
        auto date = Clock.currTime!(ClockType.coarse)(UTC());
        writeDateHeader(outBuf, date);
        if (!parser.shouldKeepAlive) outBuf.put("Connection: close\r\n");
        foreach(ref hdr; headers) {
        	outBuf.put(hdr.name);
        	outBuf.put(": ");
        	outBuf.put(hdr.value);
        	outBuf.put("\r\n");
        }
        formattedWrite(outBuf, "Content-Length: %d\r\n\r\n", _body.length);
        outBuf.put(cast(const(char)[])_body);
        client.send(outBuf.data); // TODO: short-writes are quite possible
	}

	void onStart(HttpRequest req) {}

	void onChunk(HttpRequest req, const(ubyte)[] chunk) {}

	void onComplete(HttpRequest req);

//privatish stuff
	final int onMessageBegin(Parser* parser)
	{
		outBuf.clear();
		header = 0;
		pad.reset();
		state = State.url;
		return 0;
	}

	final int onUrl(Parser* parser, const(ubyte)[] chunk)
	{
		pad.put(chunk);
		return 0;
	}

	final int onBody(Parser* parser, const(ubyte)[] chunk)
	{
		onChunk(request, chunk);
		return 0;
	}

	final int onHeaderField(Parser* parser, const(ubyte)[] chunk)
	{
		final switch(state) {
			case State.url:
				url = pad.sliceStr;
				break;
			case State.value:
				headers[header].value = pad.sliceStr;
				header += 1;
				if (headers.length <= header) headers.length += 1;
				break;
			case State.field:
			case State.done:
				break;
		}
		state = State.field;
		pad.put(chunk);
		return 0;
	}

	final int onHeaderValue(Parser* parser, const(ubyte)[] chunk)
	{
		if (state == State.field) {
			headers[header].name = pad.sliceStr;
		}
		pad.put(chunk);
		state = State.value;
		return 0;
	}

	final int onHeadersComplete(Parser* parser)
	{
		headers[header].value = pad.sliceStr;
		header += 1;
		request = HttpRequest(headers[0..header], parser.method, url);
		onStart(request);
		state = State.done;
		return 0;
	}

	final int onMessageComplete(Parser* parser)
	{
		import std.stdio;
		if (state == State.done) onComplete(request);
		if (!parser.shouldKeepAlive) serving = false;
		return 0;
	}

}

// ==================================== IMPLEMENTATION DETAILS ==============================================
private:

struct ScratchPad {
	ubyte* ptr;
	size_t capacity;
	size_t last, current;

	this(size_t size) {
		ptr = cast(ubyte*)malloc(size);
		capacity = size;
	}

	void put(const(ubyte)[] slice)
	{
		enforce(current + slice.length <= capacity, "HTTP headers too long");
		ptr[current..current+slice.length] = slice[];
		current += slice.length;
	}

	const(ubyte)[] slice()
	{
		auto data = ptr[last..current];
		last = current;
		return data;
	}

	const(char)[] sliceStr()
	{
		return cast(const(char)[])slice;
	}

	void reset()
	{
		current = 0;
		last = 0;
	}

	@disable this(this);

	~this() {
		free(ptr);
		ptr = null;
	}
}

unittest
{
	auto pad = ScratchPad(1024);
	pad.put([1, 2, 3, 4]);
	pad.put([5, 6, 7]);
	assert(pad.slice == cast(ubyte[])[1, 2, 3, 4, 5, 6, 7]);
	pad.put([8, 9, 0]);
	assert(pad.slice == cast(ubyte[])[8, 9, 0]);
	pad.reset();
	assert(pad.slice == []);
	pad.put([3, 2, 1]);
	assert(pad.slice == cast(ubyte[])[3, 2, 1]);
}


string dayAsString(DayOfWeek day) {
    final switch(day) with(DayOfWeek) {
        case mon: return "Mon";
        case tue: return "Tue";
        case wed: return "Wed";
        case thu: return "Thu";
        case fri: return "Fri";
        case sat: return "Sat";
        case sun: return "Sun";
    }
}

string monthAsString(Month month){
    final switch(month) with (Month) {
        case jan: return "Jan";
        case feb: return "Feb";
        case mar: return "Mar";
        case apr: return "Apr";
        case may: return "May";
        case jun: return "Jun";
        case jul: return "Jul";
        case aug: return "Aug";
        case sep: return "Sep";
        case oct: return "Oct";
        case nov: return "Nov";
        case dec: return "Dec";
    }
}

void writeDateHeader(Output, D)(ref Output sink, D date){
    string weekDay = dayAsString(date.dayOfWeek);
    string month = monthAsString(date.month);
    formattedWrite(sink,
        "Date: %s, %02s %s %04s %02s:%02s:%02s GMT\r\n",
        weekDay, date.day, month, date.year,
        date.hour, date.minute, date.second
    );
}

unittest
{
	import std.conv, std.regex, std.stdio;
	import core.thread;

	static struct TestCase {
		string raw;
		HttpMethod method;
		string reqBody;
		HttpHeader[] expected;
		string respPat;
	}

	static class TestHttpProcessor : HttpProcessor {
		TestCase[] cases;
		const(char)[] _body;

		this(Socket sock, TestCase[] cases) {
			super(sock);
			this.cases = cases;
		}

		override void onStart(HttpRequest req) {
			_body = "";
			assert(req.method == cases.front.method, text(req.method));
			assert(req.headers == cases.front.expected, text("Unexpected:", req.headers));
		}

		override void onChunk(HttpRequest req, const(ubyte)[] chunk) {
			assert(req.method == cases.front.method, text(req.method));
			assert(req.headers == cases.front.expected, text("Unexpected:", req.headers));
			_body ~= cast(string)chunk;
			assert(_body == cases.front.reqBody, text(_body, " vs ", cases.front.reqBody));
		}

		override void onComplete(HttpRequest req) {
			respondWith(_body, 200);
			cases.popFront();
		}
	}


	auto groups = [
		[
			TestCase("GET /test HTTP/1.1\r\n" ~
	         "Host: host\r\n" ~
	         "Accept: */*\r\n" ~
	         "Connection: close\r\n" ~
	         "Content-Length: 5\r\n" ~
	         "\r\nHELLO",
	         HttpMethod.GET,
	         "HELLO",
	         [ HttpHeader("Host", "host"), HttpHeader("Accept", "*/*"), HttpHeader("Connection", "close"), HttpHeader("Content-Length", "5")],
	         `HTTP/1.1 200 OK\r\nServer: photon/simple\r\nDate: .* GMT\r\nConnection: close\r\nContent-Length: 5\r\n\r\nHELLO`
         	)
		],
		[
			TestCase("POST /test2 HTTP/1.1\r\n" ~
	         "Host: host\r\n" ~
	         "Accept: */*\r\n" ~
	         "Content-Length: 2\r\n" ~
	         "\r\nHI",
	         HttpMethod.POST,
	         "HI",
	         [ HttpHeader("Host", "host"), HttpHeader("Accept", "*/*"), HttpHeader("Content-Length", "2")],
	         `HTTP/1.1 200 OK\r\nServer: photon/simple\r\nDate: .* GMT\r\nContent-Length: 2\r\n\r\nHI`
         	),
         	TestCase("GET /test3 HTTP/1.1\r\n" ~
	         "Host: host2\r\n" ~
	         "Accept: */*\r\n" ~
	         "Content-Length: 7\r\n" ~
	         "\r\nGOODBAY",
	         HttpMethod.GET,
	         "GOODBAY",
	         [ HttpHeader("Host", "host2"), HttpHeader("Accept", "*/*"), HttpHeader("Content-Length", "7")],
	         `HTTP/1.1 200 OK\r\nServer: photon/simple\r\nDate: .* GMT\r\nContent-Length: 7\r\n\r\nGOODBAY`
         	)
		]
	];

	foreach (i, series; groups) {
		Socket[2] pair = socketPair();
		char[1024] buf;
		auto serv = new TestHttpProcessor(pair[1], series);
		auto t = new Thread({
			try {
				serv.run();
			}
			catch(Throwable t) {
				stderr.writeln("Server failed: ", t);
				throw t;
			}
		});
		t.start();
		foreach(j, tc; series) {
			pair[0].send(tc.raw);
			size_t resp = pair[0].receive(buf[]);
			assert(buf[0..resp].matchFirst(tc.respPat), text("test series:", i, "\ntest case ", j, "\n", buf[0..resp]));
		}
		pair[0].close();
		t.join();
	}
}
