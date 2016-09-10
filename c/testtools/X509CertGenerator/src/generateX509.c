// TestX509Generator.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include "generateX509Cert.h"


int main()
{
    X509CertHandle handle = createX509Auth();

    fprintf(stdout, "Key file Path : %s \n", getRSAKey(handle));

    fprintf(stdout, "Cert file Path : %s \n", getCert(handle));

    unsigned char* tp = getThumbPrint(handle);

    for (int pos = 0; pos < 19; pos++)
        printf("%02x", tp[pos]);
    printf("%02x\n", tp[19]);

    destroyX509Auth(handle);

    return 0;
}

