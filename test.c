
#include "sha256.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {  
    //read in file and open stream here
   // char* filelocation = "";
    
    if (argc > 1 && argc < 3) {
     //   filelocation = argv[1];
        
         /* 
            void sha256_init(sha256_state *state);
            void sha256_update(sha256_state *state, const uint8_t data[], int len);
            void sha256_final(sha256_state *state,  uint8_t hash[]);
            
            i'm guessing we need to initialize the sha256_state struct, then update?
         */
        
        unsigned char input1[500];
        FILE *f = fopen(argv[1], "r"); 
        fgets (input1, 50, f);
        fclose(f);
        unsigned char hash[32];
        sha256_state test;
        sha256_init(&test);
        printf("all good here\n");
        sha256_update(&test, input1, strlen(input1));
                printf("all good here\n");

        sha256_final(&test, hash);
        printf("all good here\n");
    }

        
    
    else {
    printf( "Invalid terminal arguments\nPlease use format: ./[executable] //[filelocation]\n");
    }
    return 0;
}
