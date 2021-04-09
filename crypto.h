#ifndef __CRYPTO_H___
#define __CRYPTO_H__

#include <stdint.h>

#define AFFINE_MULT         11
#define AFFINE_INC          19

#define FEISTEL_BLOCK_SIZE  8
#define FEISTEL_ROUNDS      8

#define MOD(A, B)           ((A % B) < (0) ? ((A % B) + B) : (A % B))

/*
* grabs a random byte stream of given size from /dev/urandom
*/
uint8_t *random_key_create(long size);

/*
* encrypts given plaintext using caesar's cipher and key N
*/
uint8_t* caesar_encrypt(uint8_t *plaintext, uint16_t N);

/*
* decrypts given ciphertext using caesar's cipher and key N
*/
uint8_t* caesar_decrypt(uint8_t *ciphertext, uint16_t N);

/*
* encrypts given plaintext using affine cipher using the linear function defined in cs457_crypto.h
*/
uint8_t* affine_encrypt(uint8_t *plaintext);

/*
* decrypts given plaintext using affine cipher using the linear function defined in cs457_crypto.h
*/
uint8_t* affine_decrypt(uint8_t *ciphertext);

/*
* encrypts given plaintext using one time pad, xoring every byte of the plaintext with every byte of the key
*/
uint8_t* otp_encrypt(uint8_t *plaintext, uint8_t* key, uint16_t length);

/*
* decrypts given ciphertext using one time pad, xoring every byte of the ciphertext with every byte of the key
*/
uint8_t* otp_decrypt(uint8_t *ciphertext, uint8_t* key, uint16_t length);

/*
* encrypt the given plaintext with the feistel algorithm, running for FEISTEL_ROUNDS rounds (defined in cs457_crypto.h) and creating a random key each round,
* storing it in the corresponding row of keys matrix
*/
uint8_t* feistel_encrypt(uint8_t *plaintext, uint8_t **keys, uint16_t length);

/*
* decrypts ciphertext using feistel and using the keys the encrypt function created
*/
uint8_t* feistel_decrypt(uint8_t *ciphertext, uint8_t **keys, uint16_t length);

/*
* encrypts given plaintext using given keymatrix
*/
uint8_t* playfair_encrypt(uint8_t *plaintext, uint8_t **key);

/*
* decrypts the given ciphertext using playfair and given keymatrix
*/
uint8_t* playfair_decrypt(uint8_t *ciphertext, uint8_t **key);

/*
* structs the keymatrix made from key by filling the rest of the alphabet and replacing Is with Js
*/
uint8_t **playfair_keymatrix(uint8_t *key);

#endif