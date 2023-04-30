#define _CRT_SECURE_NO_WARNINGS

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;	
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;

	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encryptedkey[2] = {0,};
	int len = 64;
	int temp = 0;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if(strcmp(argv[1],"-e") == 0){
		printf("========================Encryption========================\n");		

		char *plaintext_file = argv[2];
		FILE* fp = fopen(plaintext_file, "r");
		fgets(plaintext, sizeof(plaintext), fp);  
		printf("plaintext : %s\n", plaintext);
		
		if(strcmp(argv[2],"Caesar") == 0){
			printf("========================Caesar========================\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("ciphertext : %s\n", ciphertext);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
			memcpy(encryptedkey, op.params[1].tmpref.buffer, 1);

			FILE *fp_write = fopen("ciphertext.txt","w");
			fputs(ciphertext, fp_write);
			
			fputs(encryptedkey[0], fp_write);

			fclose(fp);
			fclose(fp_write);

		}else if(strcmp(argv[2],"RSA") == 0){
			printf("========================RSA========================\n");
			char clear[RSA_MAX_PLAIN_LEN_1024];
			char ciph[RSA_CIPHER_LEN_1024];
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
			op.params[0].tmpref.buffer = clear;
			op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[1].tmpref.buffer = ciph;
			op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, len);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENCRYPT, &op, &err_origin);

			FILE* fp_write = fopen("RSA_encrypted.txt", "w");
			fputs(ciphertext, fp_write);
			fputs(encryptedkey, fp_write);
			fclose(fp_write);
		}
		

	}else if(strcmp(argv[1],"-d") == 0){
		printf("========================Decryption========================\n");
		char *ciphertext_file = argv[2];
		FILE* fp = fopen(ciphertext_file, "r");
		fgets(ciphertext, sizeof(ciphertext), fp);
		fgets(encryptedkey, sizeof(encryptedkey), fp);

		printf("ciphertext : %s\n", ciphertext);

		memcpy(op.params[0].tmpref.buffer, encryptedkey, 1);  
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("plaintext : %s", plaintext);

		FILE *fp_write = fopen("decryption_text.txt","w");
		fputs(plaintext, fp_write);
		fclose(fp_write);

	}	
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
