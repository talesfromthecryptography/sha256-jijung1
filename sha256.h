
/*********************************************************************
* Filename:   sha256.h
* Author:     
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

/****************************** MACROS ******************************/

#define SHA256_DIGEST_SIZE 256/32 // 8
#define SHA256_BUFFER_SIZE 512/32 // 16
#define NUM_ROUNDS 64 
#define BUFFER_FULL 512/8 // 64

/****************************** TYPES ******************************/


typedef struct {
	uint32_t buffer[SHA256_BUFFER_SIZE]; // buffer input until we can transform 512 bits  16 blocks of 32-bit
	uint8_t  buffer_bytes_used; //buffer can hold up to 512/8 bits = 64 bytes so if buffer_bytes_used > BUFFER_FULL, update?

	uint64_t bit_len;                 // used in final padding

	uint32_t digest[SHA256_DIGEST_SIZE];
} sha256_state;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_state *state);
void sha256_update(sha256_state *state, const uint8_t data[], int len); //date converted to binary?
void sha256_final(sha256_state *state,  uint8_t hash[]);

#endif   // SHA256_H
