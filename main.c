#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "micro-ecc/uECC.h"
#include "nativeEndian.h"

static const struct uECC_Curve_t * _curve =  NULL;

void crypto_ecc256_init(void)
{
    // TODO: Make sure this is correctly set to secure rng
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

void print_bits(uint8_t * number, int size)
{
    printByteArrayBits(number, size);
    printf("\n");
}

void print_bytes(uint8_t * number, int size)
{
    for (int i = 0; i < size; i++) {
        printf("%02X", number[i]);
    }
    printf("\n");
}

void test_scalar_multiplication()
{
    printf("-------Running Scalar Multiplication Test!-------\n");

    uint8_t scalar[32];
    // to set scalar to 1 in first byte only uncomment following two lines and remove the for-loop
//    memset(scalar, 0, sizeof(scalar));
//    scalar[0] = 1;
    for (int i = 0; i<32; i++) {
        scalar[i] = 1;
    }

    // Printing the scalar for verification
    printf("Scalar value: ");
    print_bytes(&scalar, 32);

    uint8_t * g[64];    // point g on elliptic curve G
    uint8_t * priv_key_buffer[32];   // buffer for private key that can be dismissed

    // generate g as point on elliptic curve (public key)
    if (uECC_make_key(g, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating g!\n");
    } else {
        if (uECC_valid_public_key(g, _curve) == 1) {
            printf("Valid point g generated with value: ");
            print_bytes(g, 64);
        } else {
            printf("Invalid point g generated!\n");
            exit(1);
        }
    }

    uint8_t * mult_result[64];

    // calculate scalar multiplication of g and scalar on the curve
    if (uECC_scalar_multiplication(mult_result, g, scalar, _curve) != 1) {
        printf("Unsuccessful scalar multiplication!\n");
    } else {
        printf("Result of scalar multiplication: ");
        print_bytes(mult_result, 64);

        // make sure result is a valid public key
        if (uECC_valid_public_key(mult_result, _curve) == 1) {
            printf("Result is valid new point on the elliptic curve!\n");
        } else {
            printf("Result is invalid!\n");
        }
    }
    printf("\n");
}

void test_point_addition()
{
    printf("-------Running Point Addition Test!-------\n");

    uint8_t * p[64];
    uint8_t * q[64];
    uint8_t * result[64];
    uint8_t * priv_key_buffer[32];   // buffer for private key that can be dismissed

    // generate p as point on elliptic curve
    if (uECC_make_key(p, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating point p!\n");
    } else {
        if (uECC_valid_public_key(p, _curve) == 1) {
            printf("Valid point p generated with value: ");
            print_bytes(p, 64);
        } else {
            printf("Invalid point p generated!\n");
        }
    }

    // generate q as point on elliptic curve
    if (uECC_make_key(q, priv_key_buffer, _curve) != 1)
    {
        printf("Unsuccessful in generating point q!\n");
    } else {
        if (uECC_valid_public_key(q, _curve) == 1) {
            printf("Valid point q generated with value: ");
            print_bytes(q, 64);
        } else {
            printf("Invalid point q generated!\n");
        }
    }

    // calculate addition R = P + Q
    if (uECC_addition(result, p, q, _curve)!= 1) {
        printf("Unsuccessful addition!\n");
    } else {
        printf("Result of addition: ");
        print_bytes(result, 64);

        // make sure result is a valid public key
        if (uECC_valid_public_key(result, _curve) == 1) {
            printf("Result is valid new point on the elliptic curve!\n");
        } else {
            printf("Result is invalid!\n");
        }
    }
    printf("\n");
}

int main() {
    // init elliptic curve
    crypto_ecc256_init();

    // find out native endian setting
    //find_out_endian();

    test_scalar_multiplication();

    test_point_addition();

    return 0;
}
