#include "atarsa2.h"

int main(int argc, char *argv[])
{
    int lambda = ATARSA_BIT_LENGTH;
    mpz_t N, e, d;
    mpz_init(N);
    mpz_init(e);
    mpz_init(d);
    
    rsa_keygen(N, e, d, lambda);

    mpz_clear(N);
    mpz_clear(e);
    mpz_clear(d);
    return 0;
}

void rsa_keygen(mpz_t N, mpz_t e, mpz_t d, int lambda)
{
    mpz_t p, q, phi_N; 
    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_N);

    atarsa_primegen(p, lambda);
    atarsa_primegen(q, lambda);
    

    mpz_mul(N,p,q);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_N);
}

void atarsa_primegen(mpz_t p, int lambda) {
    mpz_t seed;
    mpz_init(seed);

    gmp_randstate_t random_state;
    gmp_randinit_default(random_state);

    mpz_set_ui(seed, rand());
    gmp_randseed_ui(random_state, seed);

    mpz_urandomb(p, random_state, lambda);

    size_t n = mpz_size(p);
    mp_limb_t t[n];
    mpz_export(t, NULL, -1, sizeof(mp_limb_t), -1, 0, p);
    t[0]     |= 0x0000000000000001;
    t[n - 1] |= 0xC000000000000000;
    mpz_import(p, n, -1, sizeof(mp_limb_t), -1, 0, t);

    mpz_nextprime(p,p);

    gmp_randclear(random_state);
    mpz_clear(seed);
}

void print_mpz(mpz_t z) {
    size_t n = mpz_size(z);
    mp_limb_t t[n];
    mpz_export(t, NULL, -1, sizeof(mp_limb_t), -1, 0, z);
    for (int i = 0; i < n; i++)
    {
        gmp_printf("t[%d] : %llu*(2^(64))^(%d)\n", i, t[i], i);
    }
    gmp_printf("\n");
}

// mpz_export( t, NULL, -1, sizeof( mp_limb_t ), -1, 0, p );
//     for (int i = 0; i < n; i++)
//     {
//         gmp_printf("t[%d] : %llu*(2^(64))^(%d)\n", i, t[i], i);
//     }
//     gmp_printf( "\n" );
//     t[0] |= 1;
//     t[n-1] |= 0xC000000000000000;

//     mpz_import( p, n, -1, sizeof( mp_limb_t ), -1, 0, t );

//     mpz_export( k, NULL, -1, sizeof( mp_limb_t ), -1, 0, p );
//     //for (int i = 0; i < n; ++i)
//         //gmp_printf("t[%d]\t : %d\t\n", i, t[i]);
//     //Make sure it is odd

//     //Make sure big enough

//     for (int i = 0; i < n; i++)
//     {
//         gmp_printf("k[%d] : %llu*(2^(64))^(%d)\n", i, k[i], i);
//     }
//     gmp_printf( "\n" );
