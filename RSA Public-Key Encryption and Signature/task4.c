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
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *p2 = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *c2 = BN_new();	
	BIGNUM *message = BN_new();
	BIGNUM *message2 = BN_new();
/*e*/	BN_hex2bn(&e, "010001");
/*n*/	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
/*d*/	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
/*mess*/	char mess[] = "I owe you $2000.";	
/*mess2*/	char mess2[] = "I owe you $3000.";
/*Initial both messages*/
	BN_hex2bn(&message, "49206f776520796f752024323030302e");	
	BN_hex2bn(&message2, "49206f776520796f752024333030302e");
/*sign both messages*/
	BN_mod_exp(c, message, d, n, ctx);
	BN_mod_exp(c2, message2, d, n, ctx);
/*print*/
	printBN("1st signed message: ", c);
	printBN("2nd signed message: ", c2);
	return 0;
}
