#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
} 
int main ()
{ 
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *s = BN_new();
	BIGNUM *s2 = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *p2 = BN_new();
	BIGNUM *message = BN_new(); 
/*n*/	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
/*e*/	BN_hex2bn(&e, "010001");
/*signature*/
	BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
/*corrupt*/
	BN_hex2bn(&s2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
/*d*/	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
/*message*/
	char mess[] = "Launch a missile.";
	BN_hex2bn(&message, "4c61756e63682061206d697373696c652e");
/*decrypt*/
	BN_mod_exp(p, s, e, n, ctx);
/*decrypt corrupt*/
	BN_mod_exp(p2, s2, e, n, ctx);
/*print*/
	printBN("Value: ", message);
/*print decrypt*/
	printBN("Decrypted signature: ", p);
/*print corrupt*/
	printBN("Decrypted signature(corrupt): ", p2);
	return 0;
}
