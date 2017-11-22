#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>


void main()
{
    char buf[20];
    size_t nbytes;
    ssize_t bytes_read;
    int fd;



    nbytes = sizeof(buf);
    bytes_read = read(0/*fd*/, buf, nbytes);

    if (bytes_read == -1)
        printf("Error while trying to read.\n");
    else
        printf("Read: <%s>\n", buf);
}