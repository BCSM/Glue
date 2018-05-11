#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>
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

int verify(char *buf){
	int doctor_ID;
	hexread((char*)&doctor_ID, 4, buf, 8);
	doctor_ID = ntohl((uint32_t) doctor_ID);	

	char record_signature_x[32];
	char record_signature_y[32];
	hexread(record_signature_x, 32, &buf[9], 64);
	hexread(record_signature_y, 32, &buf[74], 64);

	char PatientInfo_IV[12];
	char PatientInfo_Data[16];
	char PatientInfo_MAC[16];
	hexread(PatientInfo_IV, 12, &buf[139], 24);
	hexread(PatientInfo_Data, 16, &buf[164], 32);
	hexread(PatientInfo_MAC, 16, &buf[197], 32);

	char tmpPK_x[32];
	char tmpPK_y[32];
	hexread(tmpPK_x, 32, &buf[230], 64);
	hexread(tmpPK_y, 32, &buf[295], 64);

	char derived_key_xor[16];
	hexread(derived_key_xor, 16, &buf[360], 32);

	char PatientID_IV[12];
	char PatientID_Data[16];
	char PatientID_MAC[16];
	hexread(PatientID_IV, 12, &buf[393], 24);
	hexread(PatientID_Data, 16, &buf[418], 32);
	hexread(PatientID_MAC, 16, &buf[451], 32);
	
	printf("Doctor ID = %d\n", doctor_ID);

	int sock;
	struct sockaddr_in coniksAddr;
	unsigned short coniksPort = 6601;
	char coniksIP[] = "127.0.0.1";
	
	if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		vrferror("Cannot create socket to the CONIKS proxy");
	}

	memset(&coniksAddr, 0, sizeof(coniksAddr));
	coniksAddr.sin_family = AF_INET;
	coniksAddr.sin_addr.s_addr = inet_addr(coniksIP);
	coniksAddr.sin_port = htons(coniksPort);

	if(connect(sock, (struct sockaddr *) &coniksAddr, sizeof(coniksAddr)) < 0){
		vrferror("Cannot connect to the CONIKS proxy");
	}

	char request[100];
	sprintf(request, "%d\n", doctor_ID);
	send(sock, request, strlen(request), 0);

	char response[64 * 2 + 1];
	memset(response, 0, sizeof(response));
	int response_len = recv(sock, response, 64 * 2 + 1, 0);

	if(response_len != 64 * 2 + 1){
		printf("No!\n");
		return 0;
	}else{
		printf("%s\n", response);
	}
	close(sock);

	char doctor_PK_x[32];
	char doctor_PK_y[32];
	hexread(doctor_PK_x, 32, response, 64);
	hexread(doctor_PK_y, 32, &response[65], 64);

	char rx_be_signed[1000];
	memcpy(rx_be_signed, PatientInfo_IV, 12);
	memcpy(&rx_be_signed[12], PatientInfo_Data, 16);
	memcpy(&rx_be_signed[28], PatientInfo_MAC, 16);

	memcpy(&rx_be_signed[44], tmpPK_x, 32);
	memcpy(&rx_be_signed[76], tmpPK_y, 32);

	memcpy(&rx_be_signed[108], derived_key_xor, 16);

	memcpy(&rx_be_signed[124], PatientID_IV, 12);
	memcpy(&rx_be_signed[136], PatientID_Data, 16);
	memcpy(&rx_be_signed[152], PatientID_MAC, 16);

	// total: 168
	
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	EC_KEY *public_key = NULL;
	BIGNUM *bn_pub_x = NULL;
	BIGNUM *bn_pub_y = NULL;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	BIGNUM *prev_bn_r = NULL;
	BIGNUM *prev_bn_s = NULL;
	EC_POINT *public_point = NULL;

	bn_pub_x = BN_lebin2bn((unsigned char*) doctor_PK_x, sizeof(uint8_t) * 32, 0);
	bn_pub_y = BN_lebin2bn((unsigned char*) doctor_PK_y, sizeof(uint8_t) * 32, 0);

	if(bn_pub_x == NULL || bn_pub_y == NULL){
		printf("load doctor PK failed\n");
		return 0;
	}

	bn_r = BN_lebin2bn((unsigned char*) record_signature_x, sizeof(uint32_t) * 32 / sizeof(uint32_t), 0);
	bn_s = BN_lebin2bn((unsigned char*) record_signature_y, sizeof(uint32_t) * 32 / sizeof(uint32_t), 0);

	if(bn_r == NULL || bn_s == NULL){
                printf("load the record signature failed\n");
                return 0;
        }

	public_point = EC_POINT_new(ec_group);

	if(public_point == NULL){
		printf("fail to initialize a public point\n");
		return 0;
	}

	if(1 != EC_POINT_set_affine_coordinates_GFp(ec_group, public_point, bn_pub_x, bn_pub_y, NULL)){
		printf("fail to write the point.\n");
		return 0;
	}

	if(1 != EC_POINT_is_on_curve(ec_group, public_point, NULL)){
		printf("point not on the curve\n");
		return 0;
	}

	public_key = EC_KEY_new();
	if(public_key == NULL){
		printf("no space for the empty public key.\n");
		return 0;
	}

	if(1 != EC_KEY_set_group(public_key, ec_group)){
		printf("fail to set the group.\n");
		return 0;
	}

	if(1 != EC_KEY_set_public_key(public_key, public_point)){
		printf("fail to set the public key.\n");
		return 0;
	}

	unsigned char sha_result;
	unsigned char digest[32] = {0};

	if(NULL == SHA256((const unsigned char *) rx_be_signed, 168, (unsigned char*) digest)){
		printf("fail to calculate the SHA256\n");
		return 0;
	}

	ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
	if(ecdsa_sig == NULL){
		printf("cannot generate empty signature\n");
		return 0;
	} 

	ECDSA_SIG_get0(ecdsa_sig, (const BIGNUM **)&prev_bn_r, (const BIGNUM **)&prev_bn_s);
	if(prev_bn_r) BN_clear_free(prev_bn_r);
	if(prev_bn_s) BN_clear_free(prev_bn_s);

	if(1 != ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s)){
		ECDSA_SIG_free(ecdsa_sig);
		printf("fail to load the signature\n");
		return 0;
	}

	int valid = 0;
	valid = ECDSA_do_verify(digest, 32, ecdsa_sig, public_key);
	if(valid == -1){
		printf("signature bad\n");
	}else{
		printf("signature ok\n");
	}

	if (bn_pub_x)
		BN_clear_free(bn_pub_x);
	if (bn_pub_y)
		BN_clear_free(bn_pub_y);
	if (public_point)
		EC_POINT_clear_free(public_point);
	if (ecdsa_sig) {
		ECDSA_SIG_free(ecdsa_sig);
		bn_r = NULL;
		bn_s = NULL;
	}
	if (public_key)
		EC_KEY_free(public_key);
	if (bn_r)
		BN_clear_free(bn_r);
	if (bn_s)
		BN_clear_free(bn_s);

	EC_GROUP_free(ec_group);

	if(valid == -1){
		return 0;
	}else{
		return 1;
	}
}

int main(){
	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(6602);
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);

	int listen_sock;
	if ((listen_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		printf("could not create listen socket\n");
		return 1;
	}

	if ((bind(listen_sock, (struct sockaddr *)&server_address,
	          sizeof(server_address))) < 0) {
		printf("could not bind socket\n");
		return 1;
	}

	int wait_size = 16;
	if (listen(listen_sock, wait_size) < 0) {
		printf("could not open socket for listening\n");
		return 1;
	}

	struct sockaddr_in client_address;
	int client_address_len = 0;

	while (1) {
		int sock;
		if ((sock =
		         accept(listen_sock, (struct sockaddr *)&client_address,
		                &client_address_len)) < 0) {
			printf("could not open a socket to accept data\n");
			return 1;
		}

		int n = 0;
		int maxlen = 450;
		char buffer[500];

		printf("client connected with ip address: %s\n",
		       inet_ntoa(client_address.sin_addr));

		memset(buffer, 0, maxlen);

		n = recv(sock, buffer, maxlen, 0);
		printf("received: '%s'\n", buffer);

		int result = verify(buffer);
		char string[100];
		sprintf(string, "%d", result);

		send(sock, string, 1, 0);
		close(sock);
	}

	close(listen_sock);
	return 0;
}

