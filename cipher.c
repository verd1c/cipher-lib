#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "crypto.h"

void print_full(FILE* f, uint8_t *buffer, uint8_t *encrypted, uint8_t *decrypted, char *alg);

int main(int argc, char** argv){
    FILE *f, *out;
    int i, z, len, caesar = 0, affine = 0, otp = 0, playfair = 0, feistel = 0, redirecting = 0, encrypting = 0, full = 0;
    char *buffer = 0;
    uint8_t *decrypted, *encrypted, *key, **keys;
    long length;

    if(argc < 3){
        printf("error: usage: ./cipher input [-c | -a | -o | -p | -f] [cipher args] [-ENC | -DEC] [-out outputfile]\n");
        exit(0);
    }
    
    // Read file
    f = fopen(argv[1], "rb");
    if(f){
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = malloc(length);
        if(buffer){
            fread(buffer, 1, length, f);
            fclose(f);
        }else{
            printf("error: could not read from file\n");
            fclose(f);
            exit(0);
        }
    }

    // Get wether encrypting, decrypting or full
    full = 1;
    for(i = 0; i < argc; i++){
        if(strcmp("-ENC", argv[i]) == 0){
            full = 0;
            encrypting = 1;
        }else if(strcmp("-DEC", argv[i]) == 0){
            full = 0;
            encrypting = 0;
        }
    }

    // Check if we're redirecting
    out = stdout;
    for(i = 0; i < argc; i++){
        if(strcmp("-out", argv[i]) == 0){
            redirecting = 1;
            if(argc < i + 2){
                printf("error: output redirection requires extra argument: file name\n");
                exit(0);
            }

            // Get file
            out = fopen(argv[i + 1], "w");
            if(!out){
                printf("error: could not open output file for writting\n");
            }
            break;
        }
    }

    // Get cipher arg
    if(argv[2][0] != '-' || strlen(argv[2]) < 2){
        printf("error: unknown cipher argument\n");
        exit(0);
    }

    switch(argv[2][1]){
    case 'c':
        caesar = 1;

        if(argc < 4){
            printf("error: caesar's cipher requires extra argument: N\n");
            exit(0);
        }

        if(full){
            encrypted = caesar_encrypt(buffer, atoi(argv[3]));
            decrypted = caesar_decrypt(encrypted, atoi(argv[3]));
            print_full(out, buffer, encrypted, decrypted, "Caesar's Cipher");
        }else if(encrypting){
            encrypted = caesar_encrypt(buffer, atoi(argv[3]));
            fprintf(out, (char*)encrypted);
        }else{
            decrypted = caesar_decrypt(buffer, atoi(argv[3]));
            fprintf(out, (char*)decrypted);
        }

        break;
    case 'a':
        affine = 1;

        if(full){
            encrypted = affine_encrypt(buffer);
            decrypted = affine_decrypt(encrypted);
            print_full(out, buffer, encrypted, decrypted, "Affine Encrypt");
        }else if(encrypting){
            encrypted = affine_encrypt(buffer);
            fprintf(out, (char*)encrypted);
        }else{
            decrypted = affine_decrypt(buffer);
            fprintf(out, (char*)decrypted);
        }

        break;
    case 'o':
        otp = 1;

        if(!full){
            printf("error: only full print allowed for one time pad and feistel\n");
            exit(0);
        }

        len = strlen(buffer);
        key = random_key_create(len);

        // Only fullprint for otp
        encrypted = otp_encrypt(buffer, key, len);
        decrypted = otp_decrypt(encrypted, key, len);
        print_full(out, buffer, encrypted, decrypted, "One Time Pad");

        break;
    case 'p':
        playfair = 1;

        if(argc < 4){
            printf("error: playfair requires extra argument: keystring\n");
            exit(0);
        }
        keys = playfair_keymatrix(argv[3]);

        if(full){
            encrypted = playfair_encrypt(buffer, keys);
            decrypted = playfair_decrypt(encrypted, keys);
            print_full(out, buffer, encrypted, decrypted, "Playfair");
        }else if(encrypting){
            encrypted = playfair_encrypt(buffer, keys);
            fprintf(out, (char*)encrypted);
        }else{
            decrypted = playfair_decrypt(buffer, keys);
            fprintf(out, (char*)decrypted);
        }

        break;
    case 'f':
        feistel = 1;

        if(!full){
            printf("error: only full print allowed for one time pad and feistel\n");
            exit(0);
        }

        len = strlen(buffer);
        keys = malloc(FEISTEL_ROUNDS * sizeof(uint8_t*));
        for(z = 0; z < FEISTEL_ROUNDS; z++){
            keys[z] = malloc(4 * sizeof(uint8_t));
        }

        // Only fullprint for feistel
        encrypted = feistel_encrypt(buffer, keys, len);
        decrypted = feistel_decrypt(encrypted, keys, len);
        print_full(out, buffer, encrypted, decrypted, "Feistel Cipher");

        break;
    default:
        printf("error: uknown argument -%c\n", argv[2][1]);
        exit(0);
    }

    //if(redirecting) fclose(out);
    return 0;
}

void print_full(FILE *f, uint8_t *buffer, uint8_t *encrypted, uint8_t *decrypted, char *alg){
    fprintf(f, "================================================\n");
    fprintf(f, "| Encrypting using %s\n", alg);
    fprintf(f, "================================================\n");
    fprintf(f, "| Original : %s\n| Encrypted: %s\n", (char*)buffer, (char*)encrypted);
    fprintf(f, "| Decrypting...\n");
    fprintf(f, "| Encrypted: %s\n| Decrypted: %s\n", (char*)encrypted, (char*)decrypted);
    fprintf(f, "================================================\n");
    return;
}