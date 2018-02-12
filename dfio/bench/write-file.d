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
    spawn({
        int fd = open("write.txt", O_RDWR | O_CREAT | O_TRUNC, std.conv.octal!644);
        if (fd < 0) {
            stderr.writefln("Error opening fd = %d", fd);
            assert(0);
        }
        char[] buf = "Write Test".dup;
        long r = core.sys.posix.unistd.write(fd, buf.ptr, buf.length);
        logf("return r = %d\n", r);
        if (r >= 0)
            logf("return  = %s\n", buf[0..r]);
    });
    runFibers();
}
