/*

        Name: zkbdf_verify.c
        Author: Tan Teik Guan
        Description: Verify function for VDF realization using ZKBoo with PCP optimization. Modified from MPC_SHA256_VERIFIER.c
*/

/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include "shared.h"


int NUM_ROUNDS = 100;
int NUM_LOOPS = 1;

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}

#define CH(e,f,g) ((e & f) ^ ((~e) & g))

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
	if (!(value & 0x01))
		value++;
	return (int) value % modulo;
}


int main(int argc, char * argv[]) {
	setbuf(stdout, NULL);
	init_EVP();
	openmp_thread_setup();
	char CHALLENGE[BLOCK_SIZE];
	char ek[BLOCK_SIZE];
	
        if (argc != 4)
        {
                printf("Usage: %s <number of rounds (e.g. 20, 40, 60, 80, 100)> <challenge (Max %d char> <eval key (Max %d char)>\n",argv[0],MSG_SIZE,MSG_SIZE);
                return -1;
        }
        NUM_ROUNDS = atoi(argv[1]);
	memset(CHALLENGE,0,sizeof(CHALLENGE));
	strncpy(CHALLENGE,argv[2],MSG_SIZE);
	memset(ek,0,sizeof(ek));
	strncpy(ek,argv[3],MSG_SIZE);

	int PCProunds = (int) ceil(log(NUM_ROUNDS)/log(2));
	int Totalselected = 0;
	unsigned char PCPselected[NUM_ROUNDS];
	unsigned char tempBuf[64];
	unsigned char hashBuf[NUM_ROUNDS*32];
	unsigned char rootHash[32];
	int tempBufPtr;
	int Nextselected;
	int failed = 0;

	printf("Iterations of PCP: %d\n", PCProunds);

	int i;
	i = strlen(ek);
	printf("length of ek: %d\n",i);
	unsigned char input[BLOCK_SIZE];
	memset(input,0,sizeof(input));
	for (int j=0;j<i;j++)
		input[j] = ek[j];

	
	a as[2][PCProunds];
	z zs[2][PCProunds];
	unsigned char MerkleBranch[PCProunds][(32*2*PCProunds)];
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "pcp%i-%i.bin", NUM_ROUNDS,PCProunds);
	file = fopen(outputFile, "rb");
	if (!file) {
		printf("Unable to open file!");
		return -1;
	}
	memset(rootHash,0,sizeof(rootHash));
	memset(hashBuf,0,sizeof(hashBuf));
	memset(MerkleBranch,0,PCProunds*32*2*PCProunds);
	fread(rootHash,32,1,file);
	fread(hashBuf,32,NUM_ROUNDS,file);

	memset(tempBuf,0,sizeof(tempBuf));
	memcpy(&(tempBuf[32]),rootHash,32);
	sha256(tempBuf,tempBuf,64*8);
	tempBufPtr = 0;
	memset(PCPselected,0,sizeof(PCPselected));
	
	while (Totalselected < PCProunds)
	{
		Nextselected = GetNextSelected(NUM_ROUNDS,tempBuf,&tempBufPtr);
		if (!PCPselected[Nextselected])
		{
			PCPselected[Nextselected] = 1;
			Totalselected++;
		}
		if (tempBufPtr >= 32)
		{
			sha256(tempBuf,tempBuf,64*8);
			tempBufPtr = 0;
		}
	}
	for (int j = 0; j < PCProunds;j++)
	{
		fread(MerkleBranch[j],64,PCProunds,file);
		fread(&(as[0][j]), sizeof(a), 1, file);
		fread(&(zs[0][j]), sizeof(z), 1, file);
		fread(&(as[1][j]), sizeof(a), 1, file);
		fread(&(zs[1][j]), sizeof(z), 1, file);

	}
	fclose(file);

	struct timeval begin, delta;
	gettimeofday(&begin,NULL);

for(int loops=0;loops<NUM_LOOPS;loops++)
{

	uint32_t y1[8];
	uint32_t y2[8];
	reconstruct(as[0][0].yp1[0],as[0][0].yp1[1],as[0][0].yp1[2],y1);
	reconstruct(as[0][0].yp2[0],as[0][0].yp2[1],as[0][0].yp2[2],y2);
	printf("Received output for H(ek): ");
	for(int i=0;i<8;i++) {
		printf("%02X", y1[i]);
	}
	printf("\n");
	printf("Received output for Hmac(ek,challenge): ");
	for(int i=0;i<8;i++) {
		printf("%02X", y2[i]);
	}
	printf("\n");

	{
		SHA256_CTX ctx;
		unsigned char expectedhash[SHA256_DIGEST_LENGTH];
		int l;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, input, strlen(input));
        	SHA256_Final(expectedhash, &ctx);

		for (l=0;l<8;l++)
		{
			uint32_t temp;
			// to take care of big endian

			unsigned char tempc[4];
			tempc[0] = expectedhash[l*4+3];
			tempc[1] = expectedhash[l*4+2];
			tempc[2] = expectedhash[l*4+1];
			tempc[3] = expectedhash[l*4];
 
			memcpy(&temp,tempc,4);
			if (temp != y1[l])
			{
				printf("hash does not match !!\n");
				return -1;
			}
		}
	}
	int es[2][PCProunds*2];
	unsigned char plaintext[2][PCProunds][16];
	int branchdone;
	int Nextselected = 0;;
	for (int i=0; i<(PCProunds); i++)
	{
		SHA256_CTX ctx;
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &(zs[0][i]), sizeof(z));
		SHA256_Final(hash, &ctx);

		while ((PCPselected[Nextselected] != 1) && (Nextselected<NUM_ROUNDS))
			Nextselected++;
	
		if (memcmp(hash,&(hashBuf[Nextselected*32]),32))
		{
			printf("Hash Not Verified %d\n", i);
			failed = 1;
			continue;
		}		
		memcpy(&(plaintext[0][i]),&(hashBuf[(Nextselected-1)*32]),16);
		if (Nextselected>1)
			memcpy(&(plaintext[1][i]),&(hashBuf[(Nextselected-2)*32]),16);
		else
			memset(&(plaintext[1][i]),0x30,16);
		Nextselected++;
		if (memcmp(hash,&(MerkleBranch[i][32]),32))
		{
			printf("Hash branch Not Verified %d\n", i);
			failed = 1;
			continue;
		}		
		
//	#pragma omp parallel for
		for (int k = 0; k < (PCProunds-1); k++)
		{
			unsigned char branchhash[32];
			if (!failed)
			{
				sha256(branchhash,&(MerkleBranch[i][k*64]),64*8);
				if (memcmp(branchhash,&(MerkleBranch[i][(k+1)*64]),32))
				{
					if (memcmp(branchhash,&(MerkleBranch[i][(k+1)*64+32]),32))
					{
						printf("Hash branch not verified %d %d\n",k,i);
						failed = 1;
					}
				}
			}
		}	
		if (failed)
			continue;	

		sha256(hash,&(MerkleBranch[i][(PCProunds-1)*64]),64*8);
		if (memcmp(hash,rootHash,32))
		{
			printf("root hash not verified %d \n",i);
			failed = 1;
		}

		if (failed)
			continue;	
		
		H3(y1,y2,&(as[0][i]), 1, &(es[0][i]));
		H3(y1,y2,&(as[1][i]), 1, &(es[1][i]));
	}

	if (!failed)
	{
		#pragma omp parallel for
		for(int i = 0; i<(PCProunds); i++) {
			int verifyResult = verify(as[0][i], CHALLENGE, es[0][i], plaintext[0][i], zs[0][i]);
			if (verifyResult != 0) {
				printf("Not Verified %d\n", i);
				failed = 1;
			}
			else
			{
				int verifyResult = verify(as[1][i], CHALLENGE, es[1][i], plaintext[1][i], zs[1][i]);
				if (verifyResult != 0) {
					printf("Not previous Verified %d \n", i);
					failed = 1;
				}
			}
		}
	}
}

	if (!failed)
		printf("verified ok\n");
	
	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;

	printf("Total time for %d loops: %ju miliseconds\n", NUM_LOOPS,(uintmax_t)inMilli);
	printf("Time for 1 loop: %ju miliseconds\n", (uintmax_t)inMilli/NUM_LOOPS);
		
	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
