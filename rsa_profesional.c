// Compile with: gcc rsa_profesional.c -o rsa_profesional -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define RSA_KEYLEN 4096
#define RSA_PUB_EXP 65537
#define MSG_MAXLEN (RSA_KEYLEN/8 - 11)   // PKCS1 v1.5 overhead
#define CIPH_MAXLEN (RSA_KEYLEN/8)

void print_hex(const char *label, const unsigned char *buf, int len) {
    printf("%s", label);
    for (int i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main() {
    int ret;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned char msg[MSG_MAXLEN + 1];
    unsigned char encrypted[CIPH_MAXLEN];
    unsigned char decrypted[MSG_MAXLEN + 1];
    int encrypted_length, decrypted_length;

    //  Generete password RSA 4096 bits
    printf("generating RSA password %d bits...\n", RSA_KEYLEN);
    bne = BN_new();
    if (!bne) handle_openssl_error();
    if (!BN_set_word(bne, RSA_PUB_EXP)) handle_openssl_error();

    rsa = RSA_new();
    if (!RSA_generate_key_ex(rsa, RSA_KEYLEN, bne, NULL)) handle_openssl_error();

    //  show public password in pem
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, rsa);
    size_t pub_len = BIO_pending(pub);
    char *pub_key = malloc(pub_len + 1);
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = 0;
    printf("\npublic password PEM:\n%s\n", pub_key);
    free(pub_key);
    BIO_free(pub);

    //  read user message
    printf("Introduce message (máx %d bytes): ", MSG_MAXLEN);
    fflush(stdout);
    if (!fgets((char *)msg, sizeof(msg), stdin)) {
        fprintf(stderr, "Error leyendo mensaje\n");
        exit(1);
    }
    // clean line jump
    size_t msg_len = strcspn((char *)msg, "\n");
    msg[msg_len] = '\0';

    // 4. RSA encryption with padding PKCS#1 v1.5
    encrypted_length = RSA_public_encrypt(msg_len, msg, encrypted, rsa, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        fprintf(stderr, "Error  RSA.\n");
        handle_openssl_error();
    }
    print_hex("\nencrypted message (hex):\n", encrypted, encrypted_length);

    //  Decrypt RSA
    decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        fprintf(stderr, "Error in decryption RSA.\n");
        handle_openssl_error();
    }
    decrypted[decrypted_length] = '\0';

    printf("\ndecrypted message :\n%s\n", decrypted);
    
    // save private password in PEM
FILE *fp = fopen("clave_privada.pem", "wb");
if (fp) {
    PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    printf("private password save in clave_privada.pem\n");
} else {
    printf("Error.\n");
}

     //free
    RSA_free(rsa);
    BN_free(bne);

    return 0;
}
