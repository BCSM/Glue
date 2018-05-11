#include <stdio.h>

int main(int argc, char** argv){
	if(argc != 2){
		printf("format: mktx <stderr file name>");
		return 0;
	}

	FILE *fp;
	fp = fopen(argv[1], "rb");

	if(fp == NULL){
		printf("Cannot open the file. Possibly the stderr file is not 0777?\n");
		return 1;
	}

	char doctor_ID[] = "00000001";
	
	char record_signature_x[32 * 2 + 10];
	char record_signature_y[32 * 2 + 10];

	char patientInfo_IV[16 * 2 + 10];
	char patientInfo_cipher[16 * 2 + 10];
	char patientInfo_MAC[16 * 2 + 10];

	char tmpPK_x[32 * 2 + 10];
	char tmpPK_y[32 * 2 + 10];

	char patientID_IV[16 * 2 + 10];
	char patientID_ciphertext[16 * 2 + 10];
	char patientID_MAC[16 * 2 + 10];

	fscanf(fp, "%*s%*s%*s");
	// skip the doctor_PK

	fscanf(fp, "%*s%s%*s%s%*s%s", patientInfo_IV, patientInfo_cipher, patientInfo_MAC);
	// get the patient Info

	fscanf(fp, "%*s%s%s", tmpPK_x, tmpPK_y);
	// get the temporary public key

	fscanf(fp, "%*s%*s");
	// skip the derived key

	fscanf(fp, "%*s%s%*s%s%*s%s", patientID_IV, patientID_ciphertext, patientID_MAC);
	// get the patientID encrypted for the government

	fscanf(fp, "%*s%s%s", record_signature_x, record_signature_y);
	// get the signature of the record

	fclose(fp);

	printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", 
		doctor_ID,
		record_signature_x,
		record_signature_y,
		patientInfo_IV,
		patientInfo_cipher,
		patientInfo_MAC,
		tmpPK_x,
		tmpPK_y,
		patientID_IV,
		patientID_ciphertext,
		patientID_MAC
	);

	return 0;
}
