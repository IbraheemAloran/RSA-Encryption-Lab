#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a){
	char *numstr = BN_bn2hex(a);
	printf("%s %s\n", msg, numstr);
	OPENSSL_free(numstr);

}
BIGNUM* computePrivKey(BIGNUM* p, BIGNUM* q, BIGNUM* e){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* p_minus_one = BN_new();
	BIGNUM* q_minus_one = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* theta = BN_new();
	BIGNUM* privKey = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(theta, p_minus_one, q_minus_one, ctx);

	
	BN_mod_inverse(privKey, e, theta, ctx);
	BN_CTX_free(ctx);
	return privKey;
}

int main()
{

//*********TASK 1**********************
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();


	BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e,"0D88C3");

    printf("TASK 1\n");
	//compute n
	BN_mul(n, p, q, ctx);
	printBN("n = p*q = ", n);

	//compute private key d
	d = computePrivKey(p,q,e);
	printBN("Private Key d = ", d);
//*********TASK 1-END**********************

//*********TASK 2**********************
    printf("\nTASK 2\n");
	BIGNUM* privKey = BN_new();
	BN_hex2bn(&privKey, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	BIGNUM* pubKey = BN_new();
	BN_hex2bn(&pubKey, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("the public key is: ", pubKey);

	
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");

	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");

	printBN("the plaintext message for task2 is: ", message);
	BIGNUM *enc = BN_new();
	BN_mod_exp(enc, message, mod, pubKey, ctx);
	//BN_CTX_free(ctx);
	printBN("the encrypted message for task2 is: ", enc);

//*********TASK 2-END**********************


//*********TASK 3**********************
    printf("\nTASK 3\n");
    BIGNUM *dec = BN_new();
    BN_mod_exp(dec, enc, privKey, pubKey, ctx);
	//BN_CTX_free(ctx);
    printBN("the decrypted message for task2 is: ", dec);
	printf("\n");

//*********TASK 3-END**********************


//*********TASK 4**********************
    printf("TASK 4\n");
    printf("plaintext message: 49206F776520796F75203030302E\n");
    BIGNUM* m = BN_new();
    BN_hex2bn(&m, "49206F776520796F75203030302E");
    BN_mod_exp(enc, m, mod, pubKey, ctx);
	//BN_CTX_free(ctx);
	printBN("the signature for task4 is: ", enc);
	
	BN_mod_exp(dec, enc, privKey, pubKey, ctx);
	//BN_CTX_free(ctx);
    printBN("the decrypted message for task4 is: ", dec);
	printf("\n");
//*********TASK 4-END**********************	




//*********TASK 5**********************
    printf("TASK 5\n");
    printf("plaintext message: 4c61756e63682061206d697373696c652e\n");
    printf("signature: 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F\n");
    BIGNUM* s = BN_new();
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");
    BN_hex2bn(&pubKey, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    
    
    BN_mod_exp(dec, s, mod, pubKey, ctx);
	//BN_CTX_free(ctx);
    printBN("the decrypted message for task5 is: ", dec);
	printf("\n");
    

    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_mod_exp(dec, s, mod, pubKey, ctx);
	//BN_CTX_free(ctx);
    printBN("the decrypted message after currupting the signature for task5 is: ", dec);
	printf("\n");
	//‘G'È
    //ñä,O´cŒè¼rm=fÈ:N¶·¾´Â”
//*********TASK 5-END**********************	

//*********TASK 6**********************
        BN_hex2bn(&pubKey, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
        printBN("public key: ",pubKey);
        
        BN_hex2bn(&s, "84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c65426a73742e5a9785d0cc92e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf289ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115e271aa6a8882");
        BIGNUM* hash = BN_new();
        BN_mod_exp(hash, s, mod, pubKey, ctx);
    printBN("the hash is: ", hash);
	printf("\n");
	
	
	printf("The pre-computed has value: 902677e610fedcdd34780e359692eb7bd199af35115105636aeb623f9e4dd053\n");
        
    


//*********TASK 6-END**********************	


	return 0;
}
