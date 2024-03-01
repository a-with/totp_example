#include "auth.h"

int main(int argc, char *argv[]){
    unsigned char secret[20]; // Secret Key
	char base32_secret[33]; // Base 32 for printing
	char base32_pretty[64]; // Pretty base32 with spaces

    RAND_bytes(secret, sizeof(secret));
	base32_encode(base32_secret, secret, sizeof(secret));

	int pi = 0;
	for(int i = 0; i < sizeof(base32_secret); i++){
		if(i > 0 && i % 4 == 0){
			base32_pretty[pi] = ' ';
			pi++;
		}
		base32_pretty[pi] = base32_secret[i];
		pi++;	
	}
	printf("Secret: %s, String: %s\n", base32_pretty, base32_secret);
	printf("otpauth://totp/Test?secret=%s\n", base32_secret);

	int counter = std::time(nullptr) / 30; // How many half minutes since epoch
	int code = generate_HOTP(secret, sizeof(secret), counter);
	printf("HOTP: %d\n", code);
	printf("Counter: %d\n", counter);

	while(1){
		printf("\nGenerate Password?");
		getchar();
		counter = std::time(nullptr) / 30;
		code = generate_HOTP(secret, sizeof(secret), counter);
		printf("HOTP: %d\n", code);
	}
}