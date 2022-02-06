/*
 * Source based on example from Keith Hedger, www.linuxquestions.org.
 *
 * Modified by Mirsad Goran Todorovac 2022-02-06
 */

#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }

    outputBuffer[64] = 0;
}

void sha256(char *string, char outputBuffer[65])
{
    unsigned char  hash[SHA256_DIGEST_LENGTH];
    int len;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

	len=strlen(string);
    SHA256_Update(&sha256, string,len);
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
    }
    outputBuffer[64] = 0;
}

char * sha256_string(const char * const strvalue)
{
    char *outputBuffer = malloc (65);
    if (outputBuffer == NULL)
	return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char *)strvalue, strlen(strvalue), hash);
    sha256_hash_string(hash, outputBuffer);
    return outputBuffer;
}

int sha256_file(char *path, char outputBuffer[65])
{
    FILE *file = fopen(path, "rb");
    if(!file) return -534;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
}

#ifdef MAIN_SHA256

int main(int argc, char **argv)
{
	char calc_hash[65];
	printf("%s\n", sha256_string(argv[1]));
	return 0;
}

#endif

