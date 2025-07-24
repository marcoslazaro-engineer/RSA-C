// Created by Marcos Lazaro
// Compile with: gcc rsadesci.c -o rsa_descifrado -lcrypto
// Use: ./rsa_descifrado <clave_privada_pem> <mensaje_cifrado_hex>
//
// Example: ./rsa_descifrado clave_privada.pem 6ad0f8... (hex)
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RSA_KEYLEN 4096
#define CIPH_MAXLEN (RSA_KEYLEN/8)
#define MSG_MAXLEN (RSA_KEYLEN/8 - 11)   // PKCS1 v1.5 overhead

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Cconvert string HEX to binary buffer
int hex2bin(const char *hex, unsigned char *bin, int max_bin) {
    int len = strlen(hex);
    if (len % 2 != 0) return -1;
    int bin_len = len / 2;
    if (bin_len > max_bin) return -1;
    for (int i = 0; i < bin_len; ++i) {
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
    }
    return bin_len;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <clave_privada_pem> <mensaje_cifrado_hex>\n", argv[0]);
        return 1;
    }

    //  Read private password PEM
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Could not open private key file");
        return 1;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        fprintf(stderr, "Error \n");
        handle_openssl_error();
    }

    //  convert encrypted HEX message to binary
    unsigned char encrypted[CIPH_MAXLEN];
    int encrypted_length = hex2bin(argv[2], encrypted, sizeof(encrypted));
    if (encrypted_length <= 0) {
        fprintf(stderr, "Error: invalid HEX encrypted message\n");
        RSA_free(rsa);
        return 1;
    }

    //  decrypt
    unsigned char decrypted[MSG_MAXLEN + 1];
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        fprintf(stderr, "Error in decryption RSA.\n");
        handle_openssl_error();
    }
    decrypted[decrypted_length] = '\0';

    printf("decrypted message:\n%s\n", decrypted);

    RSA_free(rsa);
    return 0;
}
