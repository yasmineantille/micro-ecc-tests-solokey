#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "micro-ecc/uECC.h"
#include "nativeEndian.h"

static const struct uECC_Curve_t * _curve =  NULL;

// will be overwritten
__attribute__((weak)) int ctap_generate_rng(uint8_t * dst, size_t num)
{
    printf("ctap_generate_rng() called\n");

    int i;
    printf( "Insecure RNG being used.\r\n");
    for (i = 0; i < num; i++){
        dst[i] = (uint8_t)rand();
    }
}

void crypto_ecc256_init(void)
{
    // TODO: Make sure this is correctly set to secure rng
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _curve = uECC_secp256r1();
}

void printByteArrayBits(const uint8_t* array, size_t length) {
    for (size_t i = 0; i < length; i++) {
        uint8_t byte = array[i];
        for (int j = 7; j >= 0; j--) {
            uint8_t bit = (byte >> j) & 0x01;
            printf("%u", bit);
        }
        printf(" ");
    }
    printf("\n");
}

void find_out_endian()
{
    printf("Native endian is: %d\n", nativeEndian());
}

void test_scalar_multiplication()
{
    // a scalar with value 1
    uint8_t scalar[32];
    memset(scalar, 0, sizeof(scalar));
    for (int i = 0; i<32; i++) {
        scalar[i] = 1;
    }

    // Printing the scalar for verification
    printf("Scalar value: ");
    for (int i = 0; i < sizeof(scalar); i++) {
        printf("%02x", scalar[i]);
    }
    printf("\n");
    printf("Scalar value in bits: ");
    printByteArrayBits(scalar, sizeof(scalar));
    printf("\n");

    uint8_t * g[64];
    uint8_t * priv_key_buffer[32];   // buffer for private key that can be dismissed

    // generate g as point on elliptic curve (public key)
    if (uECC_make_key(g, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating g!\n");
    } else {
        if (uECC_valid_public_key(g, _curve) == 1) {
            printf("Valid point g generated!\n");
            printf("Value of g: ");
            for(int i = 0; i < 64; i++) {
                printf("%d ", g[i]);
            }
            printf("\n");
        } else {
            printf("Invalid point g generated!\n");
        }
    }

    uint8_t * mult_buffer[64];   // buffer for scalar mult

    int result = uECC_scalar_multiplication(mult_buffer, g, scalar, _curve);
    if (result == 1)
    {
        printf("Success!\n");
        printf("Resulting point: ");
        for(int i = 0; i < 64; i++) {
            printf("%d ", mult_buffer[i]);
        }
        printf("\n");
        if (uECC_valid_public_key(mult_buffer, _curve) == 1) {
            printf("Valid new point generated!\n");
        } else {
            printf("Invalid new point generated!\n");
        }
    } else if (result == 2) {
        printf("Invalid point!");
    } else if (result == 3) {
        printf("3");
    } else if (result == 5) {
        printf("Invalid scalar");
    } else {
        printf("Unsuccessful scalar multiplication\n");
    }
}

void test_point_addition()
{
    uint8_t * p[64];
    uint8_t * q[64];
    uint8_t * result[64];
    uint8_t * priv_key_buffer[32];   // buffer for private key that can be dismissed

    // generate p as point on elliptic curve
    if (uECC_make_key(p, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating p!\n");
    } else {
        if (uECC_valid_public_key(p, _curve) == 1) {
            printf("Valid point p generated!\n");
        } else {
            printf("Invalid point p generated!\n");
        }
    }

    // generate q as point on elliptic curve
    if (uECC_make_key(q, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating q!\n");
    } else {
        if (uECC_valid_public_key(q, _curve) == 1) {
            printf("Valid point q generated!\n");
        } else {
            printf("Invalid point q generated!\n");
        }
    }

    int res = uECC_addition(result, p, q, _curve);
    printf("Result of addition: %d", res);
}

int main() {
    // init elliptic curve
    crypto_ecc256_init();

    // find out native endian setting
    //find_out_endian();

    //test_scalar_multiplication();

    test_point_addition();

    return 0;
}
