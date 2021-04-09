#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include "crypto.h"

/*
* grabs a random byte stream of given size from /dev/urandom
*/
uint8_t *random_key_create(long size){
    FILE *fptr;
    uint8_t *data;

    fptr = fopen("/dev/urandom", "r");
    data = (uint8_t*)malloc(size * sizeof(uint8_t));
    fread(data, sizeof(uint8_t), size, fptr);
    fclose(fptr);

    return data;
}

/*
* encrypts given plaintext using caesar's cipher and key N
*/
uint8_t *caesar_encrypt(uint8_t *plaintext, uint16_t N){
    uint8_t c, *ciphertext;
    int i, size;

    size = strlen(plaintext);
    ciphertext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0; i < size; i++){
        c = plaintext[i];

        // get decimal char representation
        if(c >= 'a' && c <= 'z'){
            c = c - 'a' + 36;
        }else
        if(c >= 'A' && c <= 'Z'){
            c = c - 'A' + 10;
        }else
        if(c >= '0' && c <= '9'){
            c = c - '0';
        }else{
            ciphertext[i] = c;
            continue;
        }

        // add key
        c = MOD((c + N), 62);
        
        // bring back to char representation
        if(c <= 9){
            c += '0';
        }else
        if(c <= 35){
            c = 'A' + (c - 10);
        }else{
            c = 'a' + (c - 36);
        }

        ciphertext[i] = c;

    }
    ciphertext[i] = '\0';

    return ciphertext;
}

/*
* decrypts given ciphertext using caesar's cipher and key N
*/
uint8_t *caesar_decrypt(uint8_t *ciphertext, uint16_t N){
    uint8_t c, *plaintext;
    int i, size;

    size = strlen(ciphertext);
    plaintext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0; i < size; i++){
        c = ciphertext[i];

        // get decimal char representation
        if(c >= 'a' && c <= 'z'){
            c = c - 'a' + 36;
        }else
        if(c >= 'A' && c <= 'Z'){
            c = c - 'A' + 10;
        }else
        if(c >= '0' && c <= '9'){
            c = c - '0';
        }else{
            plaintext[i] = c;
            continue;
        }

        // subtract key
        c = MOD((c - N), 62);
        
        // bring back to char representation
        if(c <= 9){
            c += '0';
        }else
        if(c <= 35){
            c = 'A' + (c - 10);
        }else{
            c = 'a' + (c - 36);
        }

        plaintext[i] = c;

    }
    plaintext[i] = '\0';

    return plaintext;
}

/*
* encrypts given plaintext using affine cipher using the linear function defined in cs457_crypto.h
*/
uint8_t *affine_encrypt(uint8_t *plaintext){
    uint8_t *ciphertext;
    int i, eq, x, size;

    size = strlen(plaintext);
    ciphertext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0; i < size; i++){

        // if symbol not in used alphabet
        if(plaintext[i] < 'A' || plaintext[i] > 'Z'){
            ciphertext[i] = plaintext[i];
            continue;
        }

        // numeric equivalent of character (only uppercase ASCII)
        x = plaintext[i] - 'A';

        // calculate affine equivalent (a*x + b) % m
        eq = AFFINE_MULT * x + AFFINE_INC;
        ciphertext[i] = 'A' + MOD(eq, 26);
    }
    ciphertext[i] = '\0';

    return ciphertext;
}

/*
* decrypts given plaintext using affine cipher using the linear function defined in cs457_crypto.h
*/
uint8_t *affine_decrypt(uint8_t *ciphertext){
    uint8_t *plaintext;
    int i, x, size, inv, eq;

    size = strlen(ciphertext);
    plaintext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    // find multiplicative inverse to inverse linear function used to encrypt
    for(i = 0; i < 26; i++){
        if((AFFINE_MULT * i) % 26 ==  1)
            inv = i;
    }

    for(i = 0; i < size; i++){

        // if symbol not in used alphabet
        // this will not cause any problems as the result on encryption
        // is modulo 26
        if(ciphertext[i] < 'A' || ciphertext[i] > 'Z'){
            plaintext[i] = ciphertext[i];
            continue;
        }

        // numeric equivalent of character (only uppercase ASCII)
        x = ciphertext[i] - 'A';

        // reverse encrypt function
        eq = inv * (x - AFFINE_INC);
        plaintext[i] = 'A' + MOD(eq, 26);
    }
    plaintext[i] = '\0';

    return plaintext;
}

/*
* preprocesses the plaintext for one time pad to use, removing all characters not in our desired alphabet
*/
static uint8_t *otp_preprocess(uint8_t *plaintext){
    uint8_t *processed;
    int size, i, j;

    size = strlen(plaintext);

    processed = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0, j = 0; i < size + 1; i++){

        // if character is in used alphabet 0-9a-zA-Z, add to processed
        if((plaintext[i] >= '0' && plaintext[i] <= '9') || (plaintext[i] >= 'a' && plaintext[i] <= 'z') || (plaintext[i] >= 'A' && plaintext[i] <= 'Z') || plaintext[i] == ' '){
            processed[j++] = plaintext[i];
        }
    }

    for(i = j; i < size + 1; i++)
        processed[i] = '\0';

    return processed;
}

/*
* encrypts given plaintext using one time pad, xoring every byte of the plaintext with every byte of the key
*/
uint8_t *otp_encrypt(uint8_t *plaintext, uint8_t* key, uint16_t length){
    uint8_t *ciphertext, *processed;
    int i, size;

    processed = otp_preprocess(plaintext);

    size = length;

    ciphertext = (uint8_t *)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0; i < size; i++){

        // xor every char with every byte of key
        ciphertext[i] = processed[i] ^ key[i];
    }
    ciphertext[i] = '\0';

    return ciphertext;
}

/*
* decrypts given ciphertext using one time pad, xoring every byte of the ciphertext with every byte of the key
*/
uint8_t *otp_decrypt(uint8_t *ciphertext, uint8_t* key, uint16_t length){
    uint8_t *plaintext;
    int i, size;

    size = length;

    plaintext = (uint8_t *)malloc((size + 1) * sizeof(uint8_t));

    for(i = 0; i < length; i++){

        // xor ciphertext with key bytes to inverse encryption
        plaintext[i] = ciphertext[i] ^ key[i];
    }
    plaintext[i] = '\0';

    return plaintext;
}

/*
* preprocesses the plaintext for feistel to use, creating extra blocks and adding padding if needed
*/
static uint8_t *preprocess_plaintext(uint8_t *plaintext){
    uint8_t *processed;
    int size, new_size, blocks, i;

    size = strlen(plaintext);

    // round up size according to feistel block size
    if(size % FEISTEL_BLOCK_SIZE != 0)
        blocks = (size / FEISTEL_BLOCK_SIZE) + 1;
    else
        blocks = size / FEISTEL_BLOCK_SIZE;

    new_size = blocks * FEISTEL_BLOCK_SIZE;

    processed = (uint8_t*)malloc((new_size + 1) * sizeof(uint8_t));

    // copy initial text
    for(i = 0; i < size; i++){
        processed[i] = plaintext[i];
    }

    // fill with null padding
    for(i = size; i < new_size; i++){
        processed[i] = '\0';
    }
    processed[i] = '\0';

    return processed;
}

/*
* flips (literally) the first and last 4 bytes of given address
*/
static void feistel_flip(uint8_t *block){
    uint8_t temp[FEISTEL_BLOCK_SIZE / 2];
    int i;

    // save left side and replace with right
    for(i = 0; i < FEISTEL_BLOCK_SIZE / 2; i++){
        temp[i] = block[i];
        block[i] = block[FEISTEL_BLOCK_SIZE / 2 + i];
    }

    // replace right side with temp
    for(i = 0; i < FEISTEL_BLOCK_SIZE / 2; i++)
        block[FEISTEL_BLOCK_SIZE / 2 + i] = temp[i];

    return;
}

/*
* the feistel round function as defined in the assignment
*/
static uint8_t *feistel_round(uint8_t *block, uint8_t *key){
    uint8_t *rounded, c;
    int i;

    rounded = (uint8_t*)malloc((FEISTEL_BLOCK_SIZE / 2) * sizeof(uint8_t));

    // get modulo of xored with key 32 bit block mod 2^32
    for(i = 0; i < FEISTEL_BLOCK_SIZE / 2; i++){
        c = block[i] * key[i];
        rounded[i] = MOD(c, (int)pow(2, 8));
    }

    return rounded;
}

/*
* encrypt the given plaintext with the feistel algorithm, running for FEISTEL_ROUNDS rounds (defined in cs457_crypto.h) and creating a random key each round,
* storing it in the corresponding row of keys matrix
*/
uint8_t *feistel_encrypt(uint8_t *plaintext, uint8_t **keys, uint16_t length){
    uint8_t *ciphertext, *processed, *rounded, *rand;
    int i, j, blocks, size, round;

    size = length;

    ciphertext = (uint8_t*)malloc(size * sizeof(uint8_t));

    // get preprocessed text with padding
    processed = preprocess_plaintext(plaintext);

    // round up size with padding
    if(size % FEISTEL_BLOCK_SIZE != 0)
        blocks = (size / FEISTEL_BLOCK_SIZE) + 1;
    else
        blocks = size / FEISTEL_BLOCK_SIZE;

    size = blocks * FEISTEL_BLOCK_SIZE;

    for(round = 0; round < FEISTEL_ROUNDS; round++){

        // create a new key and store it to corresponding row
        rand = random_key_create(4);
        memcpy(&keys[round][0], rand, 4);

        for(i = 0; i < blocks; i++){
            // get rounded
            rounded = feistel_round(processed + (i * FEISTEL_BLOCK_SIZE) + (FEISTEL_BLOCK_SIZE / 2), rand);

            // XOR with left
            for(j = 0; j < FEISTEL_BLOCK_SIZE / 2; j++){
                processed[j + (i * FEISTEL_BLOCK_SIZE)] = processed[j + (i * FEISTEL_BLOCK_SIZE)] ^ rounded[j];
            }

            // literally flip (could be implemented so much better)
            feistel_flip(processed + (i * FEISTEL_BLOCK_SIZE));
        }
    }

    return processed;
}

/*
* decrypts ciphertext using feistel and using the keys the encrypt function created
*/
uint8_t *feistel_decrypt(uint8_t *ciphertext, uint8_t **keys, uint16_t length){
    uint8_t *plaintext, *processed, *rounded, *rand;
    int i, j, blocks, size, round;

    rand = (uint8_t*)malloc(4 * sizeof(uint8_t));
    size = length;

    // round up size
    if(size % FEISTEL_BLOCK_SIZE != 0)
        blocks = (size / FEISTEL_BLOCK_SIZE) + 1;
    else
        blocks = size / FEISTEL_BLOCK_SIZE;

    size = blocks * FEISTEL_BLOCK_SIZE;

    // heap corruption on playfair so i leave it like this? (use after free????)
    processed = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));
    memcpy(processed, ciphertext, size + 1);

    for(round = 0; round < FEISTEL_ROUNDS; round++){

        // get key from key matrix for current round (set by encrypt)
        memcpy(rand, &keys[FEISTEL_ROUNDS - 1 - round][0], 4);

        for(i = 0; i < blocks; i++){
            // flip on start of round
            feistel_flip(processed + (i * FEISTEL_BLOCK_SIZE));

            // get rounded
            rounded = feistel_round(processed + (i * FEISTEL_BLOCK_SIZE) + (FEISTEL_BLOCK_SIZE / 2), rand);

            //printf("String: %p -> %p\n", processed, processed + (i * FEISTEL_BLOCK_SIZE) + (FEISTEL_BLOCK_SIZE / 2));

            // XOR with left
            for(j = 0; j < FEISTEL_BLOCK_SIZE / 2; j++){
                processed[j + (i * FEISTEL_BLOCK_SIZE)] = processed[j + (i * FEISTEL_BLOCK_SIZE)] ^ rounded[j];
            }

            
        }
    }

    return processed;
}

/*
* structs the keymatrix made from key by filling the rest of the alphabet and replacing Is with Js
*/
uint8_t **playfair_keymatrix(uint8_t *key){
    uint8_t **keymatrix, alphabet[26] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    int used[26], i, j, k, filled;

    // calloc didnt work ok
    for(i = 0; i < 26; i++)
        used[i] = 0;
        
    // 2d array
    keymatrix = (uint8_t**)malloc(5 * sizeof(uint8_t*));

    for(i = 0; i < 5; i++)
        keymatrix[i] = (uint8_t*)malloc(5 * sizeof(uint8_t));

    // fill initial key
    i = 0;
    j = 0;
    filled = 0;
    for(k = 0; k < strlen(key); k++){      
        // check if already used
        if(!used[key[k] - 'A'] && (key[k] >= 'A' && key[k] <= 'Z')){
            keymatrix[i][j] = key[k];
            j++;

            // switch row
            if(j % 5 == 0){
                i++;
                j = 0;
            }

            // set used
            used[key[k] - 'A'] = 1;
            filled++;
        }
    }

    // fill rest of the alphabet
    k = 0;
    while(filled < 25){
        // check if used
        if(!used[k] && alphabet[k] != 'I'){
            keymatrix[i][j] = alphabet[k];

            j++;

            if(j % 5 == 0){
                i++;
                j = 0;
            }

            used[k] = 1;
            filled++;
        }
        k++;
    }

    return keymatrix;
}

/*
* matches the given 2 characters on the keymatrix in an encryption fashion (positive) and returns the encrypted ones
*/
static uint8_t *playfair_encrypt_match(uint8_t **keymatrix, uint8_t *text){
    uint8_t *encoded;
    int i, j, i1, i2, j1, j2;

    encoded = (uint8_t*)malloc(2 * sizeof(uint8_t));
    
    // find in matrix
    for(i = 0; i < 5; i++){ 
        for(j = 0; j < 5; j++){
            if(keymatrix[i][j] == text[0]){
                i1 = i;
                j1 = j;
            }else if(keymatrix[i][j] == text[1]){
                i2 = i;
                j2 = j;
            }
        }
    }

    if(i1 == i2){ // same row
        encoded[0] = keymatrix[i1][(j1 + 1) % 5];
        encoded[1] = keymatrix[i2][(j2 + 1) % 5];
    }else if(j1 == j2){ // same column
        encoded[0] = keymatrix[(i1 + 1) % 5][j1];
        encoded[1] = keymatrix[(i2 + 1) % 5][j2];
    }else{ // square
        encoded[0] = keymatrix[i1][j2];
        encoded[1] = keymatrix[i2][j1];
    }

    return encoded;
}

/*
* matches the given 2 characters on the keymatrix in a decryption fashion (negative) and returns the decrypted ones
*/
static uint8_t *playfair_decrypt_match(uint8_t **keymatrix, uint8_t *text){
    uint8_t *encoded;
    int i, j, i1, i2, j1, j2;

    encoded = (uint8_t*)malloc(2 * sizeof(uint8_t));

    // find in matrix
    for(i = 0; i < 5; i++){ 
        for(j = 0; j < 5; j++){
            if(keymatrix[i][j] == text[0]){
                i1 = i;
                j1 = j;
            }else if(keymatrix[i][j] == text[1]){
                i2 = i;
                j2 = j;
            }
        }
    }

    if(i1 == i2){ // same row
        encoded[0] = keymatrix[i1][MOD((j1 - 1), 5)];
        encoded[1] = keymatrix[i2][MOD((j2 - 1), 5)];
    }else if(j1 == j2){ // same column
        encoded[0] = keymatrix[MOD((i1 - 1), 5)][j1];
        encoded[1] = keymatrix[MOD((i2 - 1), 5)][j2];
    }else{ // square
        encoded[0] = keymatrix[i1][j2];
        encoded[1] = keymatrix[i2][j1];
    }

    return encoded;
}

/*
* preprocesses the plaintext for playfair to use, setting an X at the end if the text was odd lengthed or setting X on double char appearances
* and removing special characters not in the alphabet
*/
static uint8_t *playfair_preprocess(uint8_t *text){
    uint8_t *processed, *no_specials;
    int i, j, size, wasOdd, blocks, specials = 0;

    size = strlen(text);

    // count special chars
    for(i = 0; i < size; i++){
        if(text[i] < 'A' || text[i] > 'Z'){
            specials++;
        }
    }

    // allocate for actual chars
    no_specials = (uint8_t*)malloc((size - specials + 1) * sizeof(uint8_t));

    // struct no_specials
    for(i = 0, j = 0; i < size; i++){

        // if in alphabet
        if(text[i] >= 'A' && text[i] <= 'Z'){

            // switch Is to Js
            if(text[i] != 'I')
                no_specials[j++] = text[i];
            else
                no_specials[j++] = 'J';
        }
    }
    no_specials[j] = '\0';
    size = size - specials; // new size

    // if odd, add up extra space
    wasOdd = 0;
    if(size % 2 != 0){
        size++;
        wasOdd = 1;
    }

    blocks = size / 2;

    // final processed
    processed = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    // for every 2 byte block
    for(i = 0; i < blocks; i++){

        // first char will always be what it is
        processed[i * 2] = no_specials[i * 2];

        // check if second should be X
        if(wasOdd && i == (blocks - 1)){ // if odd
            processed[(i * 2) + 1] = 'X';
        }else if(no_specials[i * 2] == no_specials[(i * 2) + 1]){ // if 2 same chars
            processed[(i * 2) + 1] = 'X';
        }else{ // if normal
            processed[(i * 2) + 1] = no_specials[(i * 2) + 1];
        }
    }
    processed[i * 2] = '\0';

    return processed;
}

/*
* encrypts given plaintext using given keymatrix
*/
uint8_t *playfair_encrypt(uint8_t *plaintext, uint8_t **key){
    uint8_t *ciphertext, *processed, *encrypted, *text;
    int i, size, blocks;

    // preprocess adding Xs and removing special chars
    processed = playfair_preprocess(plaintext);

    size = strlen(processed);
    blocks = size / 2;
    text = (uint8_t*)malloc(2 * sizeof(uint8_t));
    ciphertext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    // for every 2 byte block
    for(i = 0; i < blocks; i++){
        // get plaintext
        text[0] = processed[i * 2];
        text[1] = processed[(i * 2) + 1];

        // encrypt on matrix
        encrypted = playfair_encrypt_match(key, text);

        // set encrypted
        ciphertext[i * 2] = encrypted[0];
        ciphertext[(i * 2) + 1] = encrypted[1];
    }
    ciphertext[i * 2] = '\0';

    return ciphertext;
}

/*
* decrypts the given ciphertext using playfair and given keymatrix
*/
uint8_t *playfair_decrypt(uint8_t *ciphertext, uint8_t **key){
    uint8_t *plaintext, *processed, *encrypted, *text;
    int i, k, size, blocks;

    size = strlen(ciphertext);
    blocks = size / 2;
    text = (uint8_t*)malloc(2 * sizeof(uint8_t));
    plaintext = (uint8_t*)malloc((size + 1) * sizeof(uint8_t));

    // for every 2 byte block
    for(i = 0; i < blocks; i++){
        // get encrypted
        text[0] = ciphertext[i * 2];
        text[1] = ciphertext[(i * 2) + 1];

        // decrypt on amtrix
        encrypted = playfair_decrypt_match(key, text);

        // set decrypted
        plaintext[i * 2] = encrypted[0];
        plaintext[(i * 2) + 1] = encrypted[1];
    }

    plaintext[i * 2] = '\0';

    return plaintext;
}