#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "micro-ecc/uECC.h"
#include "nativeEndian.h"

static const struct uECC_Curve_t * curve =  NULL;


__attribute__((weak)) int ctap_generate_rng(uint8_t * dst, size_t num)
{
    int i;
    printf("Insecure RNG being used.\r\n");
    for (i = 0; i < num; i++){
        dst[i] = (uint8_t)rand();
    }
    return 1;
}

void crypto_ecc256_init(void)
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    curve = uECC_secp256r1();
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
    if (uECC_make_key(g, priv_key_buffer, curve) != 1)
    {
        printf("Unsuccessful in generating g!\n");
    } else {
        if (uECC_valid_public_key(g, curve) == 1) {
            printf("Valid point g generated with value: ");
            print_bytes(g, 64);
        } else {
            printf("Invalid point g generated!\n");
            exit(1);
        }
    }

    uint8_t * mult_result[64];

    // calculate scalar multiplication of g and scalar on the curve
    if (uECC_scalar_multiplication(mult_result, g, scalar, curve) != 1) {
        printf("Unsuccessful scalar multiplication!\n");
    } else {
        printf("Result of scalar multiplication: ");
        print_bytes(mult_result, 64);

        // make sure result is a valid public key
        if (uECC_valid_public_key(mult_result, curve) == 1) {
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
    if (uECC_make_key(p, priv_key_buffer, curve) != 1)
    {
        printf("Unsuccessful in generating point p!\n");
    } else {
        if (uECC_valid_public_key(p, curve) == 1) {
            printf("Valid point p generated with value: ");
            print_bytes(p, 64);
        } else {
            printf("Invalid point p generated!\n");
        }
    }

    // generate q as point on elliptic curve
    if (uECC_make_key(q, priv_key_buffer, curve) != 1)
    {
        printf("Unsuccessful in generating point q!\n");
    } else {
        if (uECC_valid_public_key(q, curve) == 1) {
            printf("Valid point q generated with value: ");
            print_bytes(q, 64);
        } else {
            printf("Invalid point q generated!\n");
        }
    }

    // calculate addition R = P + Q
    if (uECC_addition(result, p, q, curve) != 1) {
        printf("Unsuccessful addition!\n");
    } else {
        printf("Result of addition: ");
        print_bytes(result, 64);

        // make sure result is a valid public key
        if (uECC_valid_public_key(result, curve) == 1) {
            printf("Result is valid new point on the elliptic curve!\n");
        } else {
            printf("Result is invalid!\n");
        }
    }
    printf("\n");
}

void test_mod_inv()
{
    uint8_t * result[64];
    uint8_t * r[2];

    printf("-------Running Modular Inverse Test!-------\n");

    if (ctap_generate_rng(r, 2) != 1) {
        printf("Failed at generating r\n");
    } else {
        printf("Random r generated: ");
        print_bytes(r, 2);
    }

    if (uECC_calculate_mod_inv(result, r, curve) != 1) {
        printf("Error, calculating modular inverse of r failed\n");
    } else {
        printf("Successfully calculated modular inverse of r with value: ");
        print_bytes(result, 32);
    }
    printf("\n");
}


void test_scalar_mult_with_expected_result()
{
    printf("-------Running Scalar Multiplication with scalar 2 and expected result Test!-------\n");
    // Scalar multiplication of 2
    uint8_t scalar[32];
    memset(scalar, 0, sizeof(scalar));
    scalar[31] = 2;

    // Using a previously generated valid point
    const uint8_t point[] = {
            0x85, 0x55, 0xF4, 0x5F, 0xB8, 0x20, 0x13, 0x85, 0x83, 0xBF, 0xCF, 0xC0, 0xA7, 0x2A, 0xE0, 0xF0,
            0xF8, 0xA1, 0x69, 0x61, 0x4C, 0x15, 0xF7, 0x98, 0x74, 0x84, 0xCE, 0xD7, 0x72, 0xBC, 0x81, 0x0C,
            0xA6, 0xE0, 0xAC, 0xF1, 0x33, 0xFA, 0xD0, 0x93, 0x44, 0x26, 0x33, 0x80, 0x04, 0xC7, 0x76, 0xB5,
            0xBF, 0x92, 0x5F, 0x75, 0x5D, 0xE8, 0xD2, 0xE2, 0xBE, 0x44, 0xF6, 0xB3, 0xE4, 0xF0, 0x5F, 0x07
    };
    printf("The point for multiplication is: ");
    print_bytes(point, 64);

    uint8_t mult_result[64];
    // calculate scalar multiplication of point and scalar on the curve
    if (uECC_scalar_multiplication(mult_result, point, scalar, curve) != 1) {
        printf("Unsuccessful scalar multiplication!\n");
    } else {
        printf("Result of scalar multiplication with 2: ");
        print_bytes(mult_result, 64);

        // make sure result is a valid public key
        if (uECC_valid_public_key(mult_result, curve) != 1) {
            printf("Result is invalid!\n");
        }
    }

    const uint8_t expected_result[] = {
            0x71, 0x34, 0x89, 0x68, 0x7A, 0xDF, 0x6E, 0xC9, 0xAE, 0xFC, 0xD2, 0xAE, 0x80, 0xF6, 0x4B, 0x43,
            0x9F, 0x7A, 0x8B, 0x0D, 0xAE, 0xDC, 0xFD, 0x5D, 0xEB, 0x1D, 0x3A, 0xEF, 0x02, 0x5E, 0xA8, 0xEC,
            0x42, 0x40, 0xD8, 0xC6, 0xB5, 0xB7, 0xFC, 0x34, 0x5D, 0xBB, 0xE7, 0xF9, 0xE2, 0xB7, 0x3B, 0xDE,
            0xB3, 0xE2, 0x57, 0xB7, 0x74, 0x45, 0x6E, 0x6D, 0x57, 0x2F, 0xC0, 0xF2, 0xD7, 0x75, 0x40, 0xAF
    };

    int result = memcmp(mult_result, expected_result, sizeof(expected_result));
    if (result == 0) {
        printf("Test passed! Result of scalar multiplication returns the expected result. \n");
    } else {
        printf("Test failed.\n");
        printf("Expected result was: ");
        print_bytes(expected_result, 64);
        printf("\nHowever the received result was: ");
        print_bytes(mult_result, 64);
    }
}

int main() {
    // init elliptic curve
    crypto_ecc256_init();

    // find out native endian setting
    //find_out_endian();

    test_scalar_multiplication();

    test_point_addition();

    test_mod_inv();

    test_scalar_mult_with_expected_result();

    return 0;
}
