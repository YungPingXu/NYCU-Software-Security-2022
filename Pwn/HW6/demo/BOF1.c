#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void backdoor(){
    system("/bin/sh");
}

int main(){
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    char name[0x10];
    printf("What's your name: ");
    read(0, name, 0x100);
    return 0;
}