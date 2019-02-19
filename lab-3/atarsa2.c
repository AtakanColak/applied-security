#include "atarsa2.h"

gmp_randstate_t random_state;

int main(int argc, char *argv[])
{
    if (argc == 2)
    {
        int lambda = ATARSA_BIT_LENGTH;
        mpz_t N, e, d, c, m;
        mpz_init(N);
        mpz_init(e);
        mpz_init(d);
        mpz_init(c);
        mpz_init(m);

        srand(time(0));
        mpz_t seed;
        mpz_init(seed);

        int valid = mpz_set_str(m, argv[1], 16);

        if (valid == 0)
        {
            gmp_randinit_default(random_state);
            mpz_set_ui(seed, 0x0123456789ABCDEF);
            gmp_randseed_ui(random_state, seed);

            rsa_keygen(N, e, d, lambda);
            rsa_enc(c, m, e, N);
            print_str("Ciphertext :");
            print_str(mpz_get_str(NULL, 16, c));
            rsa_dec(c, c, d, N);

            print_str("Message :");
            print_str(mpz_get_str(NULL, 16, m));
            

            if (mpz_cmp(m, c) == 0)
            {
                print_str("Vanilla RSA works.");

                print_str("Public Key :");
                print_str(mpz_get_str(NULL, 10, N));
                print_str(mpz_get_str(NULL, 10, e));
                print_str("Private Key :");
                print_str(mpz_get_str(NULL, 10, N));
                print_str(mpz_get_str(NULL, 10, d));
            }
            else
            {
                print_str("Error.");
            }
        }
        else
        {
            print_str("Message isn't valid.");
        }

        gmp_randclear(random_state);
        mpz_clear(seed);

        mpz_clear(N);
        mpz_clear(e);
        mpz_clear(d);
        mpz_clear(c);
        mpz_clear(m);
    }
    else
        print_str("Pass a single message for encryption.");

    // print_str("Generated N:");
    // print_mpz(N);
    // print_str("Generated e:");
    // print_mpz(e);
    // print_str("Generated d:");
    // print_mpz(d);

    return 0;
}

void rsa_keygen(mpz_t N, mpz_t e, mpz_t d, int lambda)
{
    mpz_t p, q, phi_N, cmp_res;
    mpz_init(p);
    mpz_init(q);
    mpz_init(phi_N);
    mpz_init(cmp_res);

    atarsa_primegen(p, lambda);
    atarsa_primegen(q, lambda);
    print_str("P and Q generated.");

    if (mpz_cmp(p, q) > 0)
        print_str("P is greater than Q.");
    if (mpz_cmp(p, q) < 0)
        print_str("Q is greater than P.");
    else if (mpz_cmp(q, p) == 0)
        print_str("P and Q are equal.");

    mpz_mul(N, p, q);
    print_str("N generated.");

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_N, p, q);
    print_str("phi_N generated.");

    //Take e as most common e
    mpz_set_ui(e, 65537);
    int result = mpz_invert(d, e, phi_N);
    // while (!result) {
    //     mpz_urandomm(e, random_state, phi_N);
    //     mpz_gcd(cmp_res, e, phi_N);
    //     while(mpz_cmp_ui(cmp_res, 1) < 1) {
    //         mpz_urandomm(e, random_state, phi_N);
    //         mpz_gcd(cmp_res, e, phi_N);
    //     }

    // }
    if (result)
        print_str("e and d generated.");
    else
        print_str("ERROR");
    // while (1) {
    //     atarsa_random(e, lambda);
    //     mpz_gcd(cmp_res, e, p);
    //     if (mpz_cmp_ui(cmp_res, 1) != 0 ) continue;
    //     mpz_gcd(cmp_res, e, q);
    //     if (mpz_cmp_ui(cmp_res, 1) != 0 ) continue;
    //     if (mpz_cmp(e, phi_N) >= 0)       continue;
    //     mpz_invert(d, e, phi_N);
    //     break;
    // }

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_N);
    mpz_clear(cmp_res);
}

void atarsa_primegen(mpz_t p, int lambda)
{
    mpz_urandomb(p, random_state, lambda);
    size_t n = mpz_size(p);
    mp_limb_t t[n];
    mpz_export(t, NULL, -1, sizeof(mp_limb_t), -1, 0, p);
    t[0] |= 0x0000000000000001;
    t[n - 1] |= 0xC000000000000000;
    mpz_import(p, n, -1, sizeof(mp_limb_t), -1, 0, t);
    mpz_nextprime(p, p);
}

void print_mpz(mpz_t z)
{
    size_t n = mpz_size(z);
    mp_limb_t t[n];
    mpz_export(t, NULL, -1, sizeof(mp_limb_t), -1, 0, z);
    for (int i = 0; i < n; i++)
    {
        gmp_printf("t[%d] : %llu*(2^(64))^(%d)\n", i, t[i], i);
    }
    gmp_printf("\n");
}

void print_str(const char *str)
{
    if (PRINT == 1)
        gmp_printf("%s\n", str);
}

void rsa_enc(mpz_t c, mpz_t m, mpz_t e, mpz_t N)
{
    mpz_powm_sec(c, m, e, N);
}
void rsa_dec(mpz_t m, mpz_t c, mpz_t d, mpz_t N)
{
    mpz_powm_sec(m, c, d, N);
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
