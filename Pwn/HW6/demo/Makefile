all: example shellcode BOF1 BOF2_leak_canary GOT
example:
	gcc -z execstack -o example example.c
shellcode:
	gcc -o shellcode shellcode.c
BOF1:
	gcc -g -no-pie -fno-stack-protector -o BOF1 BOF1.c
BOF2_leak_canary:
	gcc -g -no-pie -o BOF2_leak_canary BOF2_leak_canary.c
GOT:
	gcc -z lazy -Wl,--dynamic-linker=/usr/src/glibc/glibc_dbg/elf/ld.so -g -o GOT GOT.c