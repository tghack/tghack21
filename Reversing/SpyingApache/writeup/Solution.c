#include <stdio.h>
#include <stdlib.h>
#include "rc4.h"
#include <string.h>



int main(int argc, char *argv[])
{

	/*if(argc<2)
	{
		printf("%s example_encode\n",argv[0]);
		return -1;
	}*/

	
	rc4_ctx ctx;
	
	rc4_setup(&ctx,"my_super_secure_password",strlen("my_super_secure_password"));
    char *tmpName = "\x57\x5C\x79\xDB\xF2\x44\xB2\x18\x91\x5B\x0D\x8E\xD9\xCF\x56\x06\x53\x9E\x00\x72\x62\x00";
    char *filename = calloc(sizeof(char),0x12uLL);
    rc4_crypt(&ctx,tmpName,filename,0x12uLL);

    printf("tmpName %s\n",filename);

    
    char encrypted_flag[102] = {0};
	size_t nr_read=0;
	
	
	FILE *fp = fopen(argv[1],"r");
	printf("%s\n", argv[1]);
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);  /* same as rewind(f); */
    
	unsigned char *buffer = malloc(fsize + 1);
	fread(buffer, 1, fsize, fp);
	fclose(fp);

	unsigned char numbers[1000]={0};
	
	size_t numbers_curs = 0;


	for(size_t buffer_curs=0x1E0;numbers_curs<100;numbers_curs++,buffer_curs+=16)
	{
		numbers[numbers_curs] = buffer[buffer_curs];
		printf("nr %d %x\n",buffer_curs,numbers[numbers_curs] );

	}
	 printf("Numbers %s\n",numbers );

	rc4_crypt(&ctx,numbers,encrypted_flag,100);
	printf("%s\n", encrypted_flag);
	




}
