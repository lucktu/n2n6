#include "n2n.h"

char * n2n_sw_version       = N2N_VERSION;
char * n2n_sw_version_full  = N2N_VERSION_FULL;
char * n2n_sw_osName        = N2N_OSNAME;
char * n2n_sw_buildDate     = __DATE__ " " __TIME__;

void print_n2n_version() {
    printf("Welcome to n2n v%s for %s, built on %s\n",
           n2n_sw_version_full, n2n_sw_osName, n2n_sw_buildDate);
    printf("Copyright 2007-16 - http://www.ntop.org\n"
           "Copyright 2017-24 - https://github.com/mxre/n2n\n"
           "Copyright 2025-26 - https://github.com/lucktu/n2n6\n");
}
