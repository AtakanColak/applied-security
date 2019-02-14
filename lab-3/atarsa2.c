#include "atarsa.h"
 
int main(int argc, char *argv[])
{
    mpz_t a,b,c;
    rsa_keygen(a,b,c, 1024);
    return 0;
}

void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda ) {
    mpz_t p;
    mpz_init(p);
   
}

void atarsa_primegen(mpz_t p, int lambda) {
    mpz_urandomb(p, gmp_randinit_mt, lambda);
    size_t n = mpz_size( p );
    mp_limb_t t[ n ];
    mpz_export(t, NULL, 1, sizeof(mp_limb_t), 1, 0, p);
    for(int i = 0; i < n; ++i)
        gmp_printf("t[%d]\t : %d\t\n", i, t[i]);
}

