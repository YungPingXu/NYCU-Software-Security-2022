#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

char flag[0x10] = "FLAG{TEST}\n";

int main(){
    FILE *fp;
    char *buf;
    buf = malloc(0x10);
    fp = fopen("/tmp/meow", "w");
    fp->_flags = 0xfbad0800;
    fp->_IO_read_end = fp->_IO_write_base = flag;
    fp->_IO_write_ptr = (char *)flag + sizeof(flag);
    fp->_IO_write_end = 0;
    fp->_fileno = 1;
    read(0, buf, 0x1000);
    fwrite(buf, 0x10, 1, fp);
    return 0;
}