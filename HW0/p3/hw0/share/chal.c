#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

char FLAG[] = "flag{redacted}";
char buf[100];
int fd;

void open_file()
{
    if (fd != 0) {
        puts("close file first");
        return;
    }
    printf("filename> ");
    scanf("%100s", buf);
    fd = open(buf, O_RDONLY);
    if (fd == -1) exit(1);
}

void read_file()
{
    if (fd == 0) return;
    read(fd, buf, 100);
}

void write_file()
{
    write(0, buf, 100);
}

void close_file()
{
    if (fd == 0) return;
    close(fd);
    fd = 0;
}

void seek_file()
{
    if (fd == 0) return;
    unsigned long offset;
    printf("offset> ");
    scanf("%lu", &offset);
    lseek(fd, offset, SEEK_SET);
}

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    int opt;
    while (1) {
        printf("1. open\n2. read\n3. write\n4. close\n5. seek\n> ");
        scanf("%u", &opt);
        switch (opt) {
        case 1: open_file(); break;
        case 2: read_file(); break;
        case 3: write_file(); break;
        case 4: close_file(); break;
        case 5: seek_file(); break;
        default: exit(0);
        }
    }
}