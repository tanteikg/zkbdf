 /*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the SHA-256 prover and verifier
 ============================================================================
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include "omp.h"

#define VERBOSE TRUE 
#define MSG_SIZE 55  // //55 is max length as we only support 447 bits = 55.875 bytes
#define BLOCK_SIZE 64  // 512 bits 

static const uint32_t ihA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

//#define ySize 736
//#define ySize 1480  // 736 * 2 + 8
#define ySize 3656 // 736 + 728* 4 + 8 

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp1[3][8];
	uint32_t yp2[3][8];
	unsigned char h[3][32];
} a;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

typedef struct _merkle
{
	int type;
	unsigned char data[32];
	struct _merkle * sibling;
	struct _merkle * parent;
	struct _merkle * previous;
	struct _merkle * next;

} Merkle;


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

/* TTG
EVP_CIPHER_CTX setupAES(unsigned char key[16]) {
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);


	// A 128 bit IV 
	unsigned char *iv = (unsigned char *)"01234567890123456";

	if(1 != EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();

	return ctx;


}
*/

void getAllRandomness(unsigned char key[16], unsigned char * plaintext, unsigned char randomness[ySize*4]) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run ySize/4 iterations

	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	unsigned char *iv = (unsigned char *)"01234567890123456";
	EVP_CIPHER_CTX_init(ctx);
	//ctx = setupAES(key);
//	unsigned char *plaintext =
//			(unsigned char *)"0000000000000000";
	int len;
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();
	for(int j=0;j<(ySize/4);j++) {
		if(1 != EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, /*strlen ((char *)plaintext)*/ 16))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
}

uint32_t getRandom32(unsigned char randomness[ySize*4], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 4);
	return ret;
}


void init_EVP() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);
}

void cleanup_EVP() {
	EVP_cleanup();
	ERR_free_strings();
}

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k, 16);
	SHA256_Update(&ctx, &v, sizeof(v));
	SHA256_Update(&ctx, r, 4);
	SHA256_Final(hash, &ctx);
}


void H3(uint32_t y1[8], uint32_t y2[8], a* as, int s, int* es) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, y1, 32);
	SHA256_Update(&ctx, y2, 32);
	SHA256_Update(&ctx, as, sizeof(a)*s);
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
				bitTracker += 2;
				i++;
			} else {
				es[i] = 1;
				bitTracker += 2;
				i++;
			}
		} else {
			if(b2 == 0) {
				es[i] = 2;
				bitTracker += 2;
				i++;
			} else {
				bitTracker += 2;
			}
		}
	}

}

void output(View v, uint32_t* result1, uint32_t* result2) {
	memcpy(result1, &v.y[ySize - 8 -8], 32);
	memcpy(result2, &v.y[ySize - 8], 32);
}

void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 8; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
}

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    omp_set_lock(&locks[type]);
  }
  else
  {
    omp_unset_lock(&locks[type]);
  }
}


unsigned long openmp_thread_id(void)
{
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void)
{
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i=0; i<CRYPTO_num_locks(); i++)
  {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void)
{
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}


int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][ySize*4], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	if(ve.y[*countY] != t) {
		return 1;
	}
	z[0] = t;
	z[1] = ve1.y[*countY];

	(*countY)++;
	return 0;
}


int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][ySize*4], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^ve.y[*countY],i);
		a[1]=GETBIT(x[1]^ve1.y[*countY],i);

		b[0]=GETBIT(y[0]^ve.y[*countY],i);
		b[1]=GETBIT(y[1]^ve1.y[*countY],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		if(GETBIT(ve.y[*countY],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(ve.y[*countY],i) ^ GETBIT(r[0],i))) {
			return 1;
		}
	}

	z[0]=x[0]^y[0]^ve.y[*countY];
	z[1]=x[1]^y[1]^ve1.y[*countY];
	(*countY)++;
	return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}


int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1, unsigned char randomness[2][ySize*4], int* randCount, int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR2(a, b, t0);
	mpc_XOR2(a, c, t1);
	if(mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(z, a, z);
	return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][ySize*4], int* randCount, int* countY) {

	uint32_t t0[3];
	mpc_XOR2(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(t0,g,z);


	return 0;
}


int verify(a a, char * Cha, int e, unsigned char * plaintext, z z) {

	unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
	H(z.ke, z.ve, z.re, hash);


	uint32_t hA[8][3];
	uint32_t innerhash[8][2];
	for (int j = 0; j<8;j++)
	{
		hA[j][0] = hA[j][1] = hA[j][2] = ihA[j];
	}

	if (memcmp(a.h[e], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	H(z.ke1, z.ve1, z.re1, hash);
	if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	free(hash);
	uint32_t* result1 = malloc(32);
	uint32_t* result2 = malloc(32);
	output(z.ve, result1, result2);
	if (memcmp(a.yp1[e], result1, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if (memcmp(a.yp2[e], result2, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	output(z.ve1, result1,result2);
	if (memcmp(a.yp1[(e + 1) % 3], result1, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if (memcmp(a.yp2[(e + 1) % 3], result2, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	free(result1);
	free(result2);

	unsigned char randomness[2][ySize*4];
	getAllRandomness(z.ke, plaintext, randomness[0]);
	getAllRandomness(z.ke1, plaintext, randomness[1]);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));
	*countY = 0;

	uint32_t w[64][2];
	int done = 5; 

	while (done-->0) // total of 5 SHA256 to be verified
	{
		for (int k = 0; k < 64;k++)
		{
			w[k][0] = w[k][1] = 0;
		}

		if ((done == 3) || (done == 1) || (done == 4))
		{
			for (int j = 0; j < 16; j++) {
				w[j][0] = (z.ve.x[j * 4] << 24) | (z.ve.x[j * 4 + 1] << 16)
									| (z.ve.x[j * 4 + 2] << 8) | z.ve.x[j * 4 + 3];
				w[j][1] = (z.ve1.x[j * 4] << 24) | (z.ve1.x[j * 4 + 1] << 16)
									| (z.ve1.x[j * 4 + 2] << 8) | z.ve1.x[j * 4 + 3];
			}
			if (done != 4)
			{
				int len = (z.ve.x[15 * 4] << 24) | (z.ve.x[15 * 4 + 1] << 16) | (z.ve.x[15 * 4 + 2] << 8) | z.ve.x[15 * 4 + 3];  
				int len324 = len/32 * 4;
				if (len > 447) // error - maximum key = 447 bits
				{
					fprintf(stderr,"error - key length > 447\n");
					return -1;
				}
				if (len % 32 == 0) // get rid of 0x80
				{
					w[len/32][0] = (z.ve.x[(len324)+1] << 16) | (z.ve.x[(len324)+ 2] << 8) | (z.ve.x[(len324) + 3]) ;
					w[len/32][1] = (z.ve1.x[(len324)+1] << 16) | (z.ve1.x[(len324) + 2] << 8) | (z.ve1.x[(len324) + 3]) ;
				}
				else if (len % 32 == 8) 
				{
					w[len/32][0] = (z.ve.x[(len324)] << 24) | (z.ve.x[(len324) + 2] << 8) | (z.ve.x[(len324) + 3]) ;
					w[len/32][1] = (z.ve1.x[(len324)] << 24) | (z.ve1.x[(len324) + 2] << 8) | (z.ve1.x[(len324) + 3]) ;
				}
				else if (len % 32 == 16)
				{
					w[len/32][0] = (z.ve.x[(len324)] << 24) | (z.ve.x[(len324) + 1] << 16) | (z.ve.x[(len324) + 3]) ;
					w[len/32][1] = (z.ve1.x[(len324)] << 24) | (z.ve1.x[(len324) + 1] << 16) | (z.ve1.x[(len324) + 3]) ;
				}
				else if (len % 32 == 24)
				{
					w[len/32][0] = (z.ve.x[(len324)] << 24) | (z.ve.x[(len324) + 1] << 16) | (z.ve.x[(len324) + 2] << 8) ;
					w[len/32][1] = (z.ve1.x[(len324)] << 24) | (z.ve1.x[(len324) + 1] << 16) | (z.ve1.x[(len324) + 2] << 8) ;
				}
				w[15][0] = 0;
				w[15][1] = 0;
				for (int j = 0; j<8;j++)
				{
					hA[j][0] = hA[j][1] = hA[j][2] = ihA[j];
				}
			
				if (done == 3)
				{
					for (int j = 0; j < 16; j++)
					{
						w[j][0] ^= 0x36363636;
						w[j][1] ^= 0x36363636;
					}
				}
				else if (done == 1)
				{
					for (int j = 0; j < 16; j++)
					{
						w[j][0] ^= 0x5c5c5c5c;
						w[j][1] ^= 0x5c5c5c5c;
					}
				}
			}
		}
		else if ((done == 2) || (done == 0))
		{
			
			unsigned char tempb[4];
			int len ; 
			unsigned char tempbuf[64];
	
			memset(tempbuf,0,sizeof(tempbuf));
			if (done == 2)
			{
				len = strlen(Cha);
				memcpy(tempbuf,Cha,len);
				tempbuf[len] = 0x80;

				for (int j = 0; j < 15; j++) {
					w[j][0] = (tempbuf[j * 4] << 24) | (tempbuf[j * 4 + 1] << 16)
										| (tempbuf[j * 4 + 2] << 8) | tempbuf[j * 4 + 3];
					w[j][1] = (tempbuf[j * 4] << 24) | (tempbuf[j * 4 + 1] << 16)
									| (tempbuf[j * 4 + 2] << 8) | tempbuf[j * 4 + 3];
				}
				len = (len*8)+512;	
			}
			else
			{
				len = 256 + 512;
				// ?? have to figure out how to copy the hash result
				for (int j = 0; j < 8; j++) {
					w[j][0] = innerhash[j][0];
					w[j][1] = innerhash[j][1];
				}
				w[8][0] = w[8][1] = 0x80000000;

			}

			memcpy(tempb,&len,sizeof(len));
			w[15][0] = (tempb[3] << 24) | (tempb[2] << 16) | (tempb[1] << 8) | tempb[0];  // is endian correct ?
			w[15][1] = (tempb[3] << 24) | (tempb[2] << 16) | (tempb[1] << 8) | tempb[0];  // is endian correct ?

			
		}

		uint32_t s0[2], s1[2];
		uint32_t t0[2], t1[2];
		for (int j = 16; j < 64; j++) {
			//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
			mpc_RIGHTROTATE2(w[j-15], 7, t0);
			mpc_RIGHTROTATE2(w[j-15], 18, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTSHIFT2(w[j-15], 3, t1);
			mpc_XOR2(t0, t1, s0);

			//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
			mpc_RIGHTROTATE2(w[j-2], 17, t0);
			mpc_RIGHTROTATE2(w[j-2], 19, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTSHIFT2(w[j-2],10,t1);
			mpc_XOR2(t0, t1, s1);
	
			//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
			if(mpc_ADD_verify(w[j-16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, j);
#endif
				return 1;
			}


			if(mpc_ADD_verify(w[j-7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, j);
#endif
				return 1;
			}
			if(mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, j);
#endif
				return 1;
			}

		}
	

		uint32_t va[2] = { hA[0][0],hA[0][1] };  // ?? is it 0 and 1
		uint32_t vb[2] = { hA[1][0],hA[1][1] };
		uint32_t vc[2] = { hA[2][0],hA[2][1] };
		uint32_t vd[2] = { hA[3][0],hA[3][1] };
		uint32_t ve[2] = { hA[4][0],hA[4][1] };
		uint32_t vf[2] = { hA[5][0],hA[5][1] };
		uint32_t vg[2] = { hA[6][0],hA[6][1] };
		uint32_t vh[2] = { hA[7][0],hA[7][1] };
		uint32_t temp1[3], temp2[3], maj[3];
		for (int i = 0; i < 64; i++) {
			//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
			mpc_RIGHTROTATE2(ve, 6, t0);
			mpc_RIGHTROTATE2(ve, 11, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTROTATE2(ve, 25, t1);
			mpc_XOR2(t0, t1, s1);
	


			//ch = (e & f) ^ ((~e) & g);
			//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];
	
			//t0 = h + s1

			if(mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}



			if(mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}

			//t1 = t0 + t1 (h+s1+ch)
			if(mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}



			t0[0] = k[i];
			t0[1] = k[i];
			if(mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}



			if(mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}

			//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
			mpc_RIGHTROTATE2(va, 2, t0);
			mpc_RIGHTROTATE2(va, 13, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTROTATE2(va, 22, t1);
			mpc_XOR2(t0, t1, s0);
	
			//maj = (a & (b ^ c)) ^ (b & c);
			//(a & b) ^ (a & c) ^ (b & c)

			if(mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}

			//temp2 = s0+maj;
			if(mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}



			memcpy(vh, vg, sizeof(uint32_t) * 2);
			memcpy(vg, vf, sizeof(uint32_t) * 2);
			memcpy(vf, ve, sizeof(uint32_t) * 2);
			//e = d+temp1;
			if(mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}

			memcpy(vd, vc, sizeof(uint32_t) * 2);
			memcpy(vc, vb, sizeof(uint32_t) * 2);
			memcpy(vb, va, sizeof(uint32_t) * 2);
			//a = temp1+temp2;

			if(mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
				printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}
		}

		if(mpc_ADD_verify(hA[0], va, hA[0], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[1], vb, hA[1], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[2], vc, hA[2], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[3], vd, hA[3], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[4], ve, hA[4], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[5], vf, hA[5], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[6], vg, hA[6], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if(mpc_ADD_verify(hA[7], vh, hA[7], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
			printf("Failing at %d", __LINE__);
#endif
			return 1;
		}
		if (done == 2)  // need to save the inner hash
		{
			for (int k = 0; k < 8; k++)
			{
				innerhash[k][0] = hA[k][0];
				innerhash[k][1] = hA[k][1];
			}
		}

	}

	free(randCount);
	free(countY);

	return 0;
}


#endif /* SHARED_H_ */
