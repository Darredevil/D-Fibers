module download_server;
import std.algorithm;
import std.conv;
import std.datetime;
import std.format;
import std.range;
import std.stdio;
import std.string;
import std.socket;
import std.uni;
import std.path;
import core.sys.posix.fcntl;
import core.thread;

import dfio;
import http.parser.core;

string FILE = "download-file";
char[24] buf;

// curl -T test.d localhost:8080 // for PUT request

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

void writeDate(Output, D)(ref Output sink, D date){
    string weekDay = dayAsString(date.dayOfWeek);
    string month = monthAsString(date.month);
    formattedWrite(sink,
        "Date: %s, %02s %s %04s %02s:%02s:%02s GMT\r\n",
        weekDay, date.day, month, date.year,
        date.hour, date.minute, date.second
    );
}

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
    scope parser = new HttpParser();
    bool reading = true;
    bool download_file = false;
    bool upload_file = false;
    string file_name;
    int connection = -1;
    parser.onMessageComplete = (parser) {
        reading = false;
    };
    parser.onHeader = (parser, HttpHeader header) {
        logf("Parser Header <%s> with value <%s>", header.name, header.value);
        if (sicmp(header.name, "connection") == 0)
            if (sicmp(header.value,"close") == 0)
                connection = 0;
            else
                connection = 1;
    };
    parser.onUrl = (parser, string data) {
        logf("Parser URL with value <%s>", data);
        if (sicmp(parser.method, "GET") == 0 && sicmp(data[1..data.length], FILE) == 0) {
            download_file = true;
        }
        else if (sicmp(parser.method, "PUT") == 0) {
            upload_file = true;
            file_name = baseName(data.dup);
        } else {
            download_file = upload_file = false;
        }
    };
    parser.onBody = (parser, HttpBodyChunk chunk) {
        string isFinal = chunk.isFinal ? "final" : "not final" ;
        //logf("A chunk of the HTTP body has been processed: %s (%s) ", chunk.buffer, isFinal);
        if (upload_file && chunk.isFinal) { // hack, assumes small upload files for now
            logf("PUT file name = %s", file_name);
            int fd = open(file_name.toStringz, O_RDWR | O_CREAT | O_TRUNC, std.conv.octal!644);
            if (fd < 0) {
                stderr.writefln("Error opening fd = %d", fd);
                assert(0);
            }
            long r = core.sys.posix.unistd.write(fd, chunk.buffer.ptr, chunk.buffer.length);
            core.sys.posix.unistd.close(fd);
        }
    };
    do {
        reading = true;
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
        logf("Request Method = %s", parser.method());
        outBuf.clear();
        bodyBuf.clear();
        if (download_file) {
            formattedWrite(bodyBuf, buf);
            download_file = false;
        }
        else if (!download_file && !upload_file) {
            formattedWrite(bodyBuf, "Hello, world!\n");
        }
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

void server() {
    Socket server = new TcpSocket();
    server.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    server.bind(new InternetAddress("localhost", 8080));
    server.listen(1000);

    logf("Started server");

    int fd = open(FILE.toStringz, O_RDONLY).checked;
    long r = core.sys.posix.unistd.read(fd, buf.ptr, buf.length);
    core.sys.posix.unistd.close(fd);

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
