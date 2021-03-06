/*

        Name: zkboo_verify.c
        Author: Tan Teik Guan
        Description: Verify function for ZKBoo for baseline comparison. Modified from MPC_SHA256_VERIFIER.c
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
#include <sys/time.h>
#include "zkboo_shared.h"

int NUM_ROUNDS = 100;

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



int main(int argc, char * argv[]) {
	setbuf(stdout, NULL);
	init_EVP();
	openmp_thread_setup();
	char CHALLENGE[MSG_SIZE+1];
	
        if (argc != 3)
        {
                printf("Usage: %s <number of rounds (e.g. 20, 40, 60, 80, 100)> <challenge>\n",argv[0]);
                return -1;
        }
        NUM_ROUNDS = atoi(argv[1]);
	memset(CHALLENGE,0,MSG_SIZE+1);
	strncpy(CHALLENGE,argv[2],MSG_SIZE);

	printf("Iterations of SHA: %d\n", NUM_ROUNDS);
	int i;
	i = strlen(CHALLENGE);
	printf("length of challenge: %d\n",i);
	unsigned char input[MSG_SIZE];
	memset(input,0,sizeof(input));
	for (int j=0;j<i;j++)
		input[j] = CHALLENGE[j];

	
	a as[NUM_ROUNDS];
	z zs[NUM_ROUNDS];
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "rb");
	if (!file) {
		printf("Unable to open file!");
		return -1;
	}
	fread(&as, sizeof(a), NUM_ROUNDS, file);
	fread(&zs, sizeof(z), NUM_ROUNDS, file);
	fclose(file);

	struct timeval begin, delta;
	gettimeofday(&begin,NULL);

for (int loops=0;loops<100;loops++)
{

	uint32_t y[8];
	reconstruct(as[0].yp[0],as[0].yp[1],as[0].yp[2],y);
	printf("Received output for H(Challenge): ");
	for(int i=0;i<8;i++) {
		printf("%02X", y[i]);
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
			if (temp != y[l])
			{
				printf("hash does not match !!\n");
				return -1;
			}
		}
	}

	int es[NUM_ROUNDS*2];
	H3(y,as, NUM_ROUNDS, es);

	 #pragma omp parallel for
	for(int i = 0; i<(NUM_ROUNDS); i++) {
		int verifyResult = verify(as[i], es[i], zs[i]);
		if (verifyResult != 0) {
			printf("Not Verified %d\n", i);
		}
	}
}
	
	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;

	printf("Total time for 100 loops: %ju miliseconds\n", (uintmax_t)inMilli);
	printf("Time taken for 1 loops: %ju miliseconds\n", (uintmax_t)inMilli/100);
	
	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
