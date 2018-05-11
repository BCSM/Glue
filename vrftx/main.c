#include <stdio.h>
#include <openssl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

void hexread(char *dest, int dest_len, const char *src, int src_len){
	int i, j, del;
	char t;

	for(i = j = 0; i < dest_len && j < src_len; i++){
		sscanf(src + j, "%2hhx%n", dest + i, &del);
		j += del;
	}
}

void vrferror(char *errorMessage){
	perror(errorMessage);
	exit(1);
}

int main(int argc, char **argv){
	if(argc < 2){
		printf("format: vrftx <Tx file>\n");
		return 0; 
	}

	char buf[450 + 10];

	FILE *fp = fopen(argv[1], "rb");
	fread(buf, 450, 1, fp);
	fclose(fp);	

	int doctor_ID;
	hexread(&doctor_ID, 4, hexread, 8);
	
	
}

