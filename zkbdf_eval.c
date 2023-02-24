/* 

	Name: zkbdf_eval.c
	Author: Tan Teik Guan
	Description: Eval function for VDF realization using ZKBoo. Modified from MPC_SHA256.c
*/
	
/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
  
 */


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "shared.h"
#include <math.h>
#include "omp.h"


#define CH(e,f,g) ((e & f) ^ ((~e) & g))


int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;
int NUM_ROUNDS = 100; 



uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}



void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;
	uint32_t t[3] = { 0 };

	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
	z[0] = t[0];
	z[1] = t[1];
	z[2] = t[2];
	views[0].y[*countY] = z[0];
	views[1].y[*countY] = z[1];
	views[2].y[*countY] = z[2];
	(*countY)++;
}



void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y[0]^c[0],i);
		b[1]=GETBIT(y[1]^c[1],i);
		b[2]=GETBIT(y[2]^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y[0]^c[0];
	z[1]=x[1]^y[1]^c[1];
	z[2]=x[2]^y[2]^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;


}


void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y^c[0],i);
		b[1]=GETBIT(y^c[1],i);
		b[2]=GETBIT(y^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y^c[0];
	z[1]=x[1]^y^c[1];
	z[2]=x[2]^y^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;

}


int sha256(unsigned char* result, unsigned char* input, int numBits) {
	uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

	int remainingBits = numBits;
	int chars;
	int i;
	while (remainingBits >= 0)
	{
		if (remainingBits > 447) 
		{
			chars = 64;
			remainingBits -= 512;
		}
		else
		{
			chars = remainingBits >> 3;
			remainingBits = -1;

		}
		unsigned char* chunk = calloc(64, 1); //512 bits
		memcpy(chunk, input, chars);
		input += chars;
		if (chars < 64)
		{	
			chunk[chars] = 0x80;

			chunk[60] = numBits >> 24;
			chunk[61] = numBits >> 16;
			chunk[62] = numBits >> 8;
			chunk[63] = numBits;
		}

		uint32_t w[64];
		for (i = 0; i < 16; i++) {
			w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16)
							| (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
		}

		uint32_t s0, s1;
		for (i = 16; i < 64; i++) {
			s0 = RIGHTROTATE(w[i - 15], 7) ^ RIGHTROTATE(w[i - 15], 18)
						^ (w[i - 15] >> 3);
			s1 = RIGHTROTATE(w[i - 2], 17) ^ RIGHTROTATE(w[i - 2], 19)
							^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a, b, c, d, e, f, g, h, temp1, temp2, maj;
		a = hA[0];
		b = hA[1];
		c = hA[2];
		d = hA[3];
		e = hA[4];
		f = hA[5];
		g = hA[6];
		h = hA[7];
	
		for (i = 0; i < 64; i++) {
			s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
	
			temp1 = h + s1 + CH(e, f, g) + k[i] + w[i];
			s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
	
	
			maj = (a & (b ^ c)) ^ (b & c);
			temp2 = s0 + maj;
	
	
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
	
		}
	
		hA[0] += a;
		hA[1] += b;
		hA[2] += c;
		hA[3] += d;
		hA[4] += e;
		hA[5] += f;
		hA[6] += g;
		hA[7] += h;
	
	}
	for (i = 0; i < 8; i++) {
		result[i * 4] = (hA[i] >> 24);
		result[i * 4 + 1] = (hA[i] >> 16);
		result[i * 4 + 2] = (hA[i] >> 8);
		result[i * 4 + 3] = hA[i];
	}
	return 0;
}

void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
	z[2] = RIGHTROTATE(x[2], i);
}




void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}





void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	mpc_AND(t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
}


void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	mpc_AND(e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);

}



int mpc_sha256(unsigned char* results[3], unsigned char inputs[3][BLOCK_SIZE], int numBits, int addView, uint32_t hA[8][3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {

/*

	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}
*/


	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t w[64][3];
	uint32_t msg[MSG_SIZE/4];

/*
	if (addMsg)
	{
		for (int j=0;j<(numBits/32);j++)
		{
			msg[j] = (addMsg[j*4]<<24) | (addMsg[j*4+1]<<16) | (addMsg[j*4+2] << 8) | (addMsg[j*4+3]);

		}

	}
*/

	for (int i =0; i<64;i++)
	{
		w[i][0]=w[i][1]=w[i][2] = 0;
	}			

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); //512 bits
		memcpy(chunks[i], inputs[i], BLOCK_SIZE /*chars*/);
/*
		chunks[i][chars] = 0x80;
		//Last 8 chars used for storing length of input without padding, in big-endian.
		//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

		chunk[60] = numBits >> 24;
		chunk[61] = numBits >> 16;
		chunks[i][62] = numBits >> 8;
		chunks[i][63] = numBits;
*/
		if (addView)
			memcpy(views[i].x, chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)
							| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];
		}
		free(chunks[i]);
	}

	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);

		mpc_RIGHTROTATE(w[j-15], 18, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		mpc_XOR(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		mpc_RIGHTROTATE(w[j-2], 19, t1);

		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		mpc_XOR(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		mpc_ADD(w[j-16], s0, t1, randomness, randCount, views, countY);
		mpc_ADD(w[j-7], t1, t1, randomness, randCount, views, countY);
		mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);

	}


	uint32_t a[3] = { hA[0][0],hA[0][1],hA[0][2] };
	uint32_t b[3] = { hA[1][0],hA[1][1],hA[1][2] };
	uint32_t c[3] = { hA[2][0],hA[2][1],hA[2][2] };
	uint32_t d[3] = { hA[3][0],hA[3][1],hA[3][2] };
	uint32_t e[3] = { hA[4][0],hA[4][1],hA[4][2] };
	uint32_t f[3] = { hA[5][0],hA[5][1],hA[5][2] };
	uint32_t g[3] = { hA[6][0],hA[6][1],hA[6][2] };
	uint32_t h[3] = { hA[7][0],hA[7][1],hA[7][2] };


	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		mpc_ADD(h, s1, t0, randomness, randCount, views, countY);


		mpc_CH(e, f, g, t1, randomness, randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);

		mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);

		mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);


		mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

		//temp2 = s0+maj;
		mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

		memcpy(h, g, sizeof(uint32_t) * 3);
		memcpy(g, f, sizeof(uint32_t) * 3);
		memcpy(f, e, sizeof(uint32_t) * 3);
		//e = d+temp1;
		mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
		memcpy(d, c, sizeof(uint32_t) * 3);
		memcpy(c, b, sizeof(uint32_t) * 3);
		memcpy(b, a, sizeof(uint32_t) * 3);
		//a = temp1+temp2;

		mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
	}

/*
	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
*/

	uint32_t hHa[8][3];

	mpc_ADD(hA[0], a, hHa[0], randomness, randCount, views, countY);
	mpc_ADD(hA[1], b, hHa[1], randomness, randCount, views, countY);
	mpc_ADD(hA[2], c, hHa[2], randomness, randCount, views, countY);
	mpc_ADD(hA[3], d, hHa[3], randomness, randCount, views, countY);
	mpc_ADD(hA[4], e, hHa[4], randomness, randCount, views, countY);
	mpc_ADD(hA[5], f, hHa[5], randomness, randCount, views, countY);
	mpc_ADD(hA[6], g, hHa[6], randomness, randCount, views, countY);
	mpc_ADD(hA[7], h, hHa[7], randomness, randCount, views, countY);

	for (int i = 0; i < 8; i++)
	{
		hA[i][0] = hHa[i][0];
		hA[i][1] = hHa[i][1];
		hA[i][2] = hHa[i][2];
	}

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];

		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
		results[2][i * 4 + 3] = hHa[i][2];
	}

	return 0;
}


int writeToFile(char filename[], void* data, int size, int numItems) {
	FILE *file;

	file = fopen(filename, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(data, size, numItems, file);
	fclose(file);
	return 0;
}




int secretShare(unsigned char* input, int numBytes, unsigned char output[3][numBytes]) {
	if(RAND_bytes(output[0], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	if(RAND_bytes(output[1], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	for (int j = 0; j < numBytes; j++) {
		output[2][j] = input[j] ^ output[0][j] ^ output[1][j];
	}
	return 0;
}


int mpc_hmac_sha256(unsigned char* results[3], unsigned char ek[3][BLOCK_SIZE], int numBytes, char * Cha, unsigned char *randomness[3], int* randCount, View views[3], int* countY) 
{
	unsigned char shares[3][BLOCK_SIZE];
	uint32_t hA[8][3];
	int i;
	unsigned char* innerhash[3],*outerhash[3];
	innerhash[0] = malloc(32);
	innerhash[1] = malloc(32);
	innerhash[2] = malloc(32);
	outerhash[0] = malloc(32);
	outerhash[1] = malloc(32);
	outerhash[2] = malloc(32);

	if (strlen(Cha) > MSG_SIZE)
	{
		printf("Input too long, aborting!");
		return -1;
	}
	for (i=0;i<8;i++)
		hA[i][0] = hA[i][1] = hA[i][2] = ihA[i];

	memset(shares[0],0,sizeof(shares[0]));
	memset(shares[1],0,sizeof(shares[1]));
	memset(shares[2],0,sizeof(shares[2]));
	for (i = 0; i < BLOCK_SIZE;i++)
	{
		shares[0][i] = ek[0][i] ^ 0x36;
		shares[1][i] = ek[1][i] ^ 0x36;
		shares[2][i] = ek[2][i] ^ 0x36;
	}
	mpc_sha256(innerhash, shares, 512, 0, hA, randomness, randCount, views, countY);

	memset(shares[0],0,sizeof(shares[0]));
	memset(shares[1],0,sizeof(shares[1]));
	memset(shares[2],0,sizeof(shares[2]));
	for (i = 0; i < strlen(Cha);i++)
	{
		shares[0][i] = Cha[i];
		shares[1][i] = Cha[i];
		shares[2][i] = Cha[i];
	}
	
	shares[0][strlen(Cha)] = shares[1][strlen(Cha)] = shares[2][strlen(Cha)] = 0x80;
	shares[0][61] = shares[1][61] = shares[2][61] = (((strlen(Cha)* 8)+512) >> 16) & 0xFF;
	shares[0][62] = shares[1][62] = shares[2][62] = (((strlen(Cha)* 8)+512) >> 8) & 0xFF;
	shares[0][63] = shares[1][63] = shares[2][63] = ((strlen(Cha)* 8)+512) & 0xFF;

	mpc_sha256(innerhash, shares, 512, 0, hA, randomness, randCount, views, countY);

	for (i=0;i<8;i++)
		hA[i][0] = hA[i][1] = hA[i][2] = ihA[i];

	memset(shares,0,3*BLOCK_SIZE);
	for (i = 0; i < BLOCK_SIZE;i++)
	{
		shares[0][i] = ek[0][i] ^ 0x5c;
		shares[1][i] = ek[1][i] ^ 0x5c;
		shares[2][i] = ek[2][i] ^ 0x5c;
	}
	mpc_sha256(outerhash, shares, 512, 0, hA, randomness, randCount, views, countY);

	memset(shares,0,3*BLOCK_SIZE);
	for (i = 0; i < 32;i++)
	{
		shares[0][i] = innerhash[0][i];
		shares[1][i] = innerhash[1][i];
		shares[2][i] = innerhash[2][i];
	}
	shares[0][32] = shares[1][32] = shares[2][32] = 0x80;
	shares[0][62] = shares[1][62] = shares[2][62] = 3;

	mpc_sha256(results, shares, 512, 0, hA, randomness, randCount, views, countY);

	free(innerhash[0]);	
	free(innerhash[1]);	
	free(innerhash[2]);	
	free(outerhash[0]);	
	free(outerhash[1]);	
	free(outerhash[2]);	
	return 0;

}

a commit(int numBytes, unsigned char shares[3][BLOCK_SIZE], char * Cha, unsigned char *randomness[3], unsigned char rs[3][4], View views[3]) {

	unsigned char* hashes[3];
	hashes[0] = malloc(32);
	hashes[1] = malloc(32);
	hashes[2] = malloc(32);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));
	uint32_t hA[8][3];
	int i;

	for (i=0;i<8;i++)
		hA[i][0] = hA[i][1] = hA[i][2] = ihA[i];

	*countY = 0;
	shares[0][numBytes] = shares[1][numBytes] = shares[2][numBytes] = 0x80;	
	shares[0][62] = shares[1][62] = shares[2][62] = ((numBytes * 8) >> 8) & 0xFF;
	shares[0][63] = shares[1][63] = shares[2][63] = (numBytes * 8) & 0xFF;
	mpc_sha256(hashes, shares, numBytes * 8, 1, hA, randomness, randCount, views, countY);

	unsigned char * hmac[3];
	hmac[0] = malloc(32);
	hmac[1] = malloc(32);
	hmac[2] = malloc(32);

	shares[0][numBytes] = shares[1][numBytes] = shares[2][numBytes] = shares[0][62] = shares[1][62] = shares[2][62] = shares[0][63] = shares[1][63] = shares[2][63] = 0;
	mpc_hmac_sha256(hmac, shares, numBytes, Cha, randomness, randCount, views, countY);

	//Explicitly add y to view
	free(randCount);
	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(hashes[0][i * 4] << 24) | (hashes[0][i * 4 + 1] << 16)
											| (hashes[0][i * 4 + 2] << 8) | hashes[0][i * 4 + 3];

		views[1].y[*countY] = 		(hashes[1][i * 4] << 24) | (hashes[1][i * 4 + 1] << 16)
											| (hashes[1][i * 4 + 2] << 8) | hashes[1][i * 4 + 3];
		views[2].y[*countY] = 		(hashes[2][i * 4] << 24) | (hashes[2][i * 4 + 1] << 16)
											| (hashes[2][i * 4 + 2] << 8) | hashes[2][i * 4 + 3];
		*countY += 1;
	}

	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 		(hmac[0][i * 4] << 24) | (hmac[0][i * 4 + 1] << 16)
											| (hmac[0][i * 4 + 2] << 8) | hmac[0][i * 4 + 3];

		views[1].y[*countY] = 		(hmac[1][i * 4] << 24) | (hmac[1][i * 4 + 1] << 16)
											| (hmac[1][i * 4 + 2] << 8) | hmac[1][i * 4 + 3];
		views[2].y[*countY] = 		(hmac[2][i * 4] << 24) | (hmac[2][i * 4 + 1] << 16)
											| (hmac[2][i * 4 + 2] << 8) | hmac[2][i * 4 + 3];
		*countY += 1;
	}

	free(countY);
	free(hashes[0]);
	free(hashes[1]);
	free(hashes[2]);
	
	free(hmac[0]);
	free(hmac[1]);
	free(hmac[2]);


	uint32_t* result11 = malloc(32);
	uint32_t* result21 = malloc(32);
	output(views[0], result11,result21);
	uint32_t* result12 = malloc(32);
	uint32_t* result22 = malloc(32);
	output(views[1], result12, result22);
	uint32_t* result13 = malloc(32);
	uint32_t* result23 = malloc(32);
	output(views[2], result13,result23);

	a a;
	memcpy(a.yp1[0], result11, 32);
	memcpy(a.yp1[1], result12, 32);
	memcpy(a.yp1[2], result13, 32);
	memcpy(a.yp2[0], result21, 32);
	memcpy(a.yp2[1], result22, 32);
	memcpy(a.yp2[2], result23, 32);

	free(result11);
	free(result12);
	free(result13);
	free(result21);
	free(result22);
	free(result23);

	return a;
}

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e],4);
	memcpy(z.re1, rs[(e + 1) % 3],4);

	return z;
}

int GetNextSelected(int size,unsigned char * data, int *dataPtr)
{
	int value=0;
	int modulo = size;
	
	while (size > 0)
	{
		value <<=8;
		value += (int) data[*dataPtr];
		size >>=8;
		(*dataPtr)++;
	}
	if (!(value & 0x01))  // will return odd number
		value++;
	return (int) value % modulo;
}

Merkle * BuildMerkleTree(int NumRounds,z * zs)
{
	int i;
	Merkle * tempNode;
	Merkle * startNode = NULL;
	Merkle * childNode;
	Merkle * prevNode;
	int done = 0;
	int odd = 0;
	unsigned char datablock[64];

	if ((!zs) || (NumRounds < 2))
		return NULL;

	prevNode = NULL;
	for (i=0; i < NumRounds;i++)
	{
		tempNode = malloc(sizeof(Merkle));
		if (i==0)
			startNode = tempNode;
		sha256(tempNode->data,(unsigned char *)&(zs[i]),sizeof(z) * 8);
		tempNode->parent = NULL;
		tempNode->type = 0;
		tempNode->next = NULL;
		tempNode->previous = prevNode;
		if (prevNode)
			prevNode->next = tempNode;
		if (!odd)
		{
			tempNode->sibling = NULL;
			odd = 1;
		}
		else
		{
			prevNode->sibling = tempNode;
			tempNode->sibling = prevNode;
			odd = 0;
		}
		prevNode = tempNode;
	}
	while (!done)
	{
		childNode = startNode;
		while (childNode->parent)
			childNode = childNode->parent;

		if (!childNode->sibling)
		{
			done = 1;
			continue;
		}
		odd = 0;
		prevNode = NULL;
		while (childNode != NULL)
		{
			tempNode = malloc(sizeof(Merkle));
			tempNode->type = 1;
			childNode->parent = tempNode;
			tempNode->previous = prevNode;	
			if (prevNode)
				prevNode->next = tempNode;
			tempNode->next = NULL;
			tempNode->parent = NULL;
			if (!odd)
			{
				tempNode->sibling = NULL;
				odd = 1;
			}
			else
			{
				prevNode->sibling = tempNode;
				tempNode->sibling = prevNode;
				odd = 0;
			}
			if (childNode->sibling)
			{
				childNode->sibling->parent = tempNode;
				memcpy(datablock,childNode->data,32);
				memcpy(&(datablock[32]),childNode->sibling->data,32);
				sha256(tempNode->data,datablock,64*8);
				childNode = childNode->sibling->next;
			}
			else
			{
				memset(datablock,0,sizeof(datablock));
				memcpy(datablock,childNode->data,32);
				sha256(tempNode->data,datablock,64*8);
				childNode = childNode->sibling;

			}
			prevNode = tempNode;
		}


	}

	return startNode;
}

void DestroyMerkleTree(Merkle * startNode)
{
	Merkle * tempNode;

	if (startNode->parent)
		DestroyMerkleTree(startNode->parent);
	startNode->parent = NULL;

	while (startNode)
	{	
		tempNode = startNode->next;
		free(startNode);
		startNode = tempNode;
	}
	return;
}
	

#define NUM_LOOPS 1

int main(int argc, char * argv[]) {
	setbuf(stdout, NULL);
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();
	char CHALLENGE[BLOCK_SIZE]; 
	char ek[BLOCK_SIZE]; //eval key is 447 bits 

	//
        if (argc != 4)
        {
                printf("Usage: %s <number of rounds (e.g. 20, 40, 60, 80, 100)> <challenge (Max %d char)> <eval key (Max %d char)>\n",argv[0],MSG_SIZE,MSG_SIZE);
                return -1;
        }

        NUM_ROUNDS = atoi(argv[1]);
	if ((NUM_ROUNDS & 0x01) || (NUM_ROUNDS < 4))
	{
		printf("Number of rounds should be even and > 4\n");
		return -1;
	}


	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	memset(CHALLENGE,0,sizeof(CHALLENGE));
	strncpy(CHALLENGE,argv[2],MSG_SIZE); //55 is max length as we only support 447 bits = 55.875 bytes
	memset(ek,0,sizeof(ek));
	strncpy(ek,argv[3],MSG_SIZE);

	int i = strlen(ek); 
	printf("ek length: %d\n", i);
	
	printf("Iterations of ZKBdf: %d\n", NUM_ROUNDS);

	unsigned char input[BLOCK_SIZE]; // 512 bits 
	memset(input,0,sizeof(input));
	memcpy(input,ek,sizeof(input));

	struct timeval begin, delta;
	gettimeofday(&begin,NULL);
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	int totalCrypto = 0;
	z* zs;

for(int loops=0;loops<NUM_LOOPS;loops++)
{

	//Generating keys
	if(RAND_bytes((unsigned char *) keys, NUM_ROUNDS*3*16) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	if(RAND_bytes((unsigned char *)rs, NUM_ROUNDS*3*4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	//Sharing secrets
	unsigned char shares[NUM_ROUNDS][3][BLOCK_SIZE];
	memset(shares,0,NUM_ROUNDS*3*BLOCK_SIZE);
	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*BLOCK_SIZE) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {

		for (int j = 0; j < i; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}
		for (int j = i; j < BLOCK_SIZE; j++) {
			shares[k][2][j] = shares[k][0][j] = shares[k][1][j] = 0;
		}

	}

	unsigned char *randomness[NUM_ROUNDS][3];
	int es[NUM_ROUNDS];
	uint32_t finalHash1[8];
	uint32_t finalHash2[8];
	zs = malloc(sizeof(z)*NUM_ROUNDS);
	int r;
for (r=0;r<NUM_ROUNDS;r++)
{
        unsigned char plaintext[16];

	memset(plaintext,0x30,sizeof(plaintext));
	if (r!=0)
	{
		SHA256_CTX ctx;
		unsigned char prevroundhash[SHA256_DIGEST_LENGTH];

                SHA256_Init(&ctx);
                SHA256_Update(&ctx, &(zs[r-1]), sizeof(z));
                SHA256_Final(prevroundhash, &ctx);

		memcpy(plaintext,prevroundhash,sizeof(plaintext));
	}
		

	//Generating randomness
//	#pragma omp parallel for
//	for(int k=0; k<(NUM_ROUNDS); k++) {
		for(int j = 0; j<3; j++) {
			randomness[r][j] = malloc((ySize*4)*sizeof(unsigned char));
			getAllRandomness(keys[r][j], plaintext, randomness[r][j]);
		}
//	}

	//Running MPC-SHA2
//	#pragma omp parallel for
//	for(int k=0; k<NUM_ROUNDS; k++) {
		as[r] = commit(i, shares[r], CHALLENGE, randomness[r], rs[r], localViews[r]);
		for(int j=0; j<3; j++) {
			free(randomness[r][j]);
		}
//	}
	
	//Committing
//	#pragma omp parallel for
//	for(int k=0; k<(NUM_ROUNDS); k++) {
		unsigned char hash1[SHA256_DIGEST_LENGTH];
		memset(hash1,0,sizeof(hash1));
		H(keys[r][0], localViews[r][0], rs[r][0], hash1);
		memcpy(as[r].h[0], &hash1, 32);
		H(keys[r][1], localViews[r][1], rs[r][1], hash1);
		memcpy(as[r].h[1], &hash1, 32);
		H(keys[r][2], localViews[r][2], rs[r][2], hash1);
		memcpy(as[r].h[2], &hash1, 32);
//	}
				
	//Generating E
	if (r==0)
	{
		for (int j = 0; j < 8; j++) {
			finalHash1[j] = as[0].yp1[0][j]^as[0].yp1[1][j]^as[0].yp1[2][j];
			finalHash2[j] = as[0].yp2[0][j]^as[0].yp2[1][j]^as[0].yp2[2][j];
		}
		printf("output H(ek) = ");
		for (int i = 0; i< 8;i++)
		{
			printf("%02X",finalHash1[i]);
		}
		printf("\n");
		printf("output HMAC(ek,Challenge) = ");
		for (int i = 0; i< 8;i++)
		{
			printf("%02X",finalHash2[i]);
		}
		printf("\n");
	}
	H3(finalHash1, finalHash2, &(as[r]), /*NUM_ROUNDS*/ 1, &(es[r]));


	//Packing Z

//	#pragma omp parallel for
//	for(int i = 0; i<(NUM_ROUNDS); i++) {
		zs[r] = prove(es[r],keys[r],rs[r], localViews[r]);
//	}

}
}
	// now to extract the PCP proofs
	int PCProunds = (int) ceil(log(NUM_ROUNDS)/log(2));
	int Totalselected = 0;
	unsigned char PCPselected[NUM_ROUNDS];
	Merkle * startNode = NULL;
	Merkle * currNode = NULL;
	Merkle * tempNode = NULL;
	Merkle * rootNode = NULL;
	unsigned char MerkleHash[64];
	unsigned char MerkleBranch[(32*2*PCProunds)+32];
	int MerkleHashPtr;
	int Nextselected;


	startNode = BuildMerkleTree(NUM_ROUNDS,zs);		
	rootNode = startNode;
	while (rootNode->parent)
		rootNode = rootNode->parent;
	memset(MerkleHash,0,sizeof(MerkleHash));
	memcpy(&(MerkleHash[32]),rootNode->data,32);
	sha256(MerkleHash,MerkleHash,64*8);
	MerkleHashPtr = 0;
	
	memset(PCPselected,0,sizeof(PCPselected));
	while (Totalselected < PCProunds)
	{
		Nextselected = GetNextSelected(NUM_ROUNDS,MerkleHash,&MerkleHashPtr);
		if (!PCPselected[Nextselected])
		{
			PCPselected[Nextselected] = 1;
			Totalselected++;
		}
		if (MerkleHashPtr >= 32)
		{
			sha256(MerkleHash,MerkleHash,64*8);
			MerkleHashPtr = 0;
		}
	}

	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;
	
	//Writing ZKBoo proofs to file
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(as, sizeof(a), NUM_ROUNDS, file);
	fwrite(zs, sizeof(z), NUM_ROUNDS, file);

	fclose(file);

	// writing PCP proofs to file 
	sprintf(outputFile, "pcp%i-%i.bin", NUM_ROUNDS,PCProunds);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	currNode = startNode;
	fwrite(rootNode->data,32,1,file);  // write the root node first
	tempNode = startNode;
	for (int k =0;k<NUM_ROUNDS;k++)
	{
		fwrite(tempNode->data,32,1,file);
		tempNode = tempNode->next;
	}
	for (int j = 0; j < NUM_ROUNDS; j++)
	{
		if (PCPselected[j])
		{
			// print current node 
			
			tempNode = currNode;
			memset(MerkleBranch,0,sizeof(MerkleBranch));
			MerkleHashPtr = 0;
			while(tempNode->parent != NULL) // write the current node	
			{
				if (tempNode->sibling)
				{
					if (tempNode->sibling == tempNode->next)
					{
						memcpy(&(MerkleBranch[MerkleHashPtr]),tempNode->data,32);
						MerkleHashPtr += 32;
						memcpy(&(MerkleBranch[MerkleHashPtr]),tempNode->sibling->data,32);
						MerkleHashPtr += 32;
					}
					else
					{
						memcpy(&(MerkleBranch[MerkleHashPtr]),tempNode->sibling->data,32);
						MerkleHashPtr += 32;
						memcpy(&(MerkleBranch[MerkleHashPtr]),tempNode->data,32);
						MerkleHashPtr += 32;
					}

				}
				else
				{
					memcpy(&(MerkleBranch[MerkleHashPtr]),tempNode->data,32);
					MerkleHashPtr += 64;
	
				}
				tempNode = tempNode->parent;
			}
			fwrite(MerkleBranch,MerkleHashPtr,1,file);  
			fwrite(&(as[j]), sizeof(a), 1, file);
			fwrite(&(zs[j]), sizeof(z), 1, file);
			fwrite(&(as[j-1]), sizeof(a), 1, file);
			fwrite(&(zs[j-1]), sizeof(z), 1, file);
		}
		currNode = currNode->next;
	}
	DestroyMerkleTree(startNode);

	fclose(file);


	free(zs);


	printf("Total time taken for %d loops: %ld mili-seconds\n",NUM_LOOPS,inMilli);
	printf("Time per loop: %ld mili-seconds\n",inMilli/NUM_LOOPS);
	printf("\n");
	printf("zkboo Proof output to file %s", outputFile);


	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
