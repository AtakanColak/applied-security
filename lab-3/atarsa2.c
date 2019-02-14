#include "atarsa2.h"

int main(int argc, char *argv[])
{
    
    atarsa_primegen(1024);
    
    return 0;
}

void rsa_keygen(mpz_t N, mpz_t e, mpz_t d, int lambda)
{
}

void atarsa_primegen(int lambda)
{
    mpz_t p, seed;
    mp_limb_t seed_l = (rand() << 32) | (rand());
    mpz_init(p);
    mpz_init(seed);
    mpz_import(seed, NULL, -1, sizeof(seed_l), -1, 0, seed_l);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed(state, seed);
    mpz_urandomb(p, state, lambda);
    size_t n = mpz_size(p);
    mp_limb_t t[n];

    mpz_export(t, NULL, -1, sizeof(mp_limb_t), -1, 0, p);
    //for (int i = 0; i < n; ++i)
        //gmp_printf("t[%d]\t : %d\t\n", i, t[i]);
    //Make sure it is odd
    t[0] |= 1;
    //Make sure big enough
    t[n-1] |= ((unsigned long) 1) << (((sizeof(mp_limb_t) - 1) * 8) + 7);
    for (int i = 0; i < n; i++)
    {
        gmp_printf("t[%d] : %llu*(2^(64))^(%d)\n", i, t[i], i);
    }
    gmp_printf( "\n" );
    gmp_randclear(state);
    mpz_clear(p);
}
