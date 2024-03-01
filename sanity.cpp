#include "auth.h"

int main(int argc, char *argv[]){
    if(argc < 2){
        printf("Usage: ./sanity (char)[secret]\n\n");
        return 1;
    }
    unsigned char secret[20];
    base32_decode(secret, argv[1]);
    int counter = std::time(nullptr) / 30;
    int code = generate_HOTP(secret, sizeof(secret), counter);
    printf("HOTP: %d\n", code);
    return 0;
}