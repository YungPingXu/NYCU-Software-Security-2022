#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

char flag[0x10] = "FLAG{TEST}\n";
char owo[] = "OWO!";

int main(){
    FILE *fp;
    char *buf;
    buf = malloc(0x10);
    fp = fopen("/tmp/meow", "r");
    fp->_flags = 0xfbad0000;
    fp->_IO_buf_base = owo;
    fp->_IO_buf_end = (char *)owo + sizeof(owo);
    fp->_IO_read_ptr = fp->_IO_read_end = 0;
    fp->_fileno = 0;
    read(0, buf, 0x1000);
    fread(buf, 0x10, 1, fp);
    if (strcmp(owo, "OWO!") != 0)
        write(1, flag, sizeof(flag));
    return 0;
}