/* App.c
*
* Copyright (C) 2006-2020 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/


#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "client-tls.h"
#include "server-tls.h"
#include <stdio.h>
#include <time.h>

#define SZ 592
/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;
	
	clock_t start_time, end_time; 
	
	
	int ret = 0;
	int sgxStatus = 0;
	int updated = 0;
    func_args args = { 0 };

	/* only print off if no command line arguments were passed in */
	if (argc != 2 || strlen(argv[1]) != 2) {
		printf("Usage:\n"
               "\tplease RUN ./App -c\n");
        return 0;
	}

    memset(t, 0, sizeof(sgx_launch_token_t));
    memset(&args,0,sizeof(args));

	ret = sgx_create_enclave(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}


    switch(argv[1][1]) {
        case 'c':
        {
        //function choosen
        int i;
        printf("fuction select:\n1:create keys and seal\n2:FirstSign for ETHadd\n3:SecondSign for tx\n");
        int res=scanf("%d",&i);
        switch(i){	
        	case 1://reopen to set 1
        	printf("create keys and seal:\n");
	    int ret;
            uint8_t sealedpriKey[SZ];
            uint8_t pubKey[64];
            for(i=0;i<50;i++){
            start_time = clock();//test time
            a(id,&ret,sealedpriKey,pubKey);
            end_time = clock();
            printf("CREATE KEY time is :%lf ", (double)(end_time - start_time) / CLOCKS_PER_SEC);}
            //store sealedpriKey
            /*
            FILE* derFile;
            derFile = fopen("sealedpriKey", "w");
                if (!derFile) {
       		 printf("error loading file\n");
      			 return -1;
    				}
    	    fwrite(sealedpriKey, 1, SZ, derFile);
    		fclose(derFile);
    		//store pubKey
    		FILE* derFile2;
            derFile2= fopen("pubKey", "w");
                if (!derFile2) {
       		 printf("error loading file\n");
      			 return -1;
    				}
    	    fwrite(pubKey, 1, 64, derFile2);
    		fclose(derFile2);
    		*/
    		break;
    		
    		case 2:
    	     printf("//First sign stage\n");
    	     
            uint8_t priKey[SZ];//sealed priv
            uint8_t signature[64];
            //uint8_t signature_save[1280];
            memset(priKey, 0, sizeof(priKey));
            memset(signature, 0, sizeof(signature));
            //memset(signature_save, 0, sizeof(signature_save));
            size_t sz;
            //read sealedpriKey
            FILE* Fileder;
            Fileder = fopen("sealedpriKey", "rb");
                if (!Fileder) {
       		 printf("error reading file\n");
      			 return -1;
    				}
    		sz=fread(priKey, 1, sizeof(priKey), Fileder);
    		//read hash(add)
    		//uint8_t MSG[1280];
    		uint8_t MSG[64];
    		FILE* Fileder2;
            Fileder2 = fopen("msgHash.txt", "r");
                if (!Fileder2) {
       		 printf("error reading file\n");
      			 return -1;
    				}
    		sz=fread(MSG, 1, sizeof(MSG), Fileder2);
    		//sign
    		//for(int i=0;i<20;i++){
    		//memcpy(MSG_SIGN,MSG+i*sizeof(MSG_SIGN),sizeof(MSG_SIGN));
    		//printf("TURN %d",i+1);
    		//start_time = clock();//test time
		ecc_sign(id,&ret,priKey,MSG,signature);
            	//end_time = clock();
            	//memcpy(signature_save+i*sizeof(signature),signature,sizeof(signature));
            	//printf("1st test time is :%lf ", (double)(end_time - start_time) / CLOCKS_PER_SEC);
            	printf("\n");
            //}
            FILE* Fileder3;
            Fileder3 = fopen("firstsign", "w");
                if (!Fileder3) {
       		 printf("error reading first sign file\n");
      			 return -1;
    				}
    		fwrite(signature, 1, sizeof(signature), Fileder3);
    		//fwrite(signature_save, 1, sizeof(signature_save), Fileder3);	
    	    fclose(Fileder3);
            fclose(Fileder2);
            fclose(Fileder);
            
            
            
            break;
            
            case 3:
            
            printf("second sign for tx:\n");
            //read sealedpriKey
            Fileder = fopen("sealedpriKey", "rb");
                if (!Fileder) {
       		 printf("error reading file\n");
      			 return -1;
    				}
    		sz=fread(priKey, 1, sizeof(priKey), Fileder);
    		//read hash(tx)
            Fileder2 = fopen("msgHash2.txt", "rb");
                if (!Fileder2) {
       		 printf("error reading file\n");
      			 return -1;
    				}
    		sz=fread(MSG, 1, sizeof(MSG), Fileder2);
    		//sign
    		
    		


		ecc_sign(id,&ret,priKey,MSG,signature);



            	printf("\n");
          
    		

            
            Fileder3 = fopen("secondsign", "w");
                if (!Fileder3) {
       		 printf("error reading file\n");
      			 return -1;
    				}
    		fwrite(signature, 1, sizeof(signature), Fileder3);	
    	    fclose(Fileder3);
            fclose(Fileder2);
            fclose(Fileder);  
            break;
            
            case 4:
            start_time = clock();
            int size_hash=4096;
            uint8_t msg[size_hash];
            uint8_t HASH_OUT[64];
            Hash_256(id,msg,HASH_OUT);
            end_time = clock();
            printf("test time is :%lf ", (double)(end_time - start_time) / CLOCKS_PER_SEC);
            //Sha3_3(id,&ret);
            break;
    		}
    		
            break;
            }

			
        

#ifdef HAVE_WOLFSSL_TEST
        case 't':
            printf("Crypt Test:\n");
            wc_test(id, &sgxStatus, &args);
            printf("Crypt Test: Return code %d\n", args.return_code);
            break;
#endif /* HAVE_WOLFSSL_TEST */

#ifdef HAVE_WOLFSSL_BENCHMARK
       case 'b':
            printf("\nBenchmark Test:\n");
            wc_benchmark_test(id, &sgxStatus, &args);
            printf("Benchmark Test: Return code %d\n", args.return_code);
            break;
#endif /* HAVE_WOLFSSL_BENCHMARK */
        default:
            printf("Unrecognized option set!\n");
            break;
    }

    return 0;
}

static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_print_string(const char *str)
{
 printf("%s", str);
}

void ocall_current_time(double* time)
{
    if(!time) return;
    *time = current_time();
    return;
}

void ocall_low_res_time(int* time)
{
    struct timeval tv;
    if(!time) return;
    *time = tv.tv_sec;
    return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

