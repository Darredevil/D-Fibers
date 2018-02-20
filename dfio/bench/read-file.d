module read_file;
import std.stdio;
import std.file;
import std.utf : byChar;
import std.string;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import dfio;

void main(){
    startloop();
    std.file.write("file.txt", "Read Test");
    spawn({

        int fd = open("file.txt", O_RDONLY);
        char[20] buf;
        long r = core.sys.posix.unistd.read(fd, buf.ptr, buf.length);
        logf("return r = %d\n", r);
        if (r >= 0)
            logf("return  = %s\n", buf[0..r]);

    });
    runFibers();
}
