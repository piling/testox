#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../toxcore/toxcore/DHT.h"
#include <endian.h>


void test_binary_encode(void);
void test_kbucket(void);
void test_distance(void);

int main(void)
{
    uint64_t len_of_test_name;
    // Reading test name(e.g. Distance) from stdin.
    fread(&len_of_test_name, sizeof len_of_test_name, 1, stdin);
    // swapping endiannes and returning len of test name
    len_of_test_name = htobe64(len_of_test_name);

    char test_name[len_of_test_name];
     // reading str of test name
    fread(&test_name, len_of_test_name, 1, stdin);

    // Determines which test case is given
    if(!memcmp(test_name, "Distance", len_of_test_name)){
        test_distance();
    }
    else if(!memcmp(test_name, "KBucketIndex", len_of_test_name)){
        test_kbucket();
    }
    else if(!memcmp(test_name, "BinaryEncode", len_of_test_name)){
        test_binary_encoding();
    }
    else{
        char failure_message[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x08" test_name;
        fwrite(failure_message, 1, sizeof failure_message, stdout);
    }

    return 0;
}


void test_binary_encode(void){
    return 0;
}

void test_kbucket(void) {
    /*
     * Given public keys.
     */
    unsigned char self_pk[32];
    unsigned char other_pk[32];

    /*
     * Reading given public keys from stdin.
     */
    fread(&self_pk, sizeof(self_pk), 1, stdin);
    fread(&other_pk, sizeof(other_pk), 1, stdin);

    putchar(1);
    putchar(1);
    putchar(bit_by_bit_cmp(self_pk, other_pk));
}


void test_distance(void){
    /*
     * Given public keys.
     */
    unsigned char origin_key[32];
    unsigned char alice_key[32];
    unsigned char bob_key[32];

    /*
     * Result types
     */
    int failure_tag = 0x00;
    int success_tag = 0x01;
    int skipped_tag = 0x02;

    /*
     * Ordering values
     */
    int less_ordering = 0x00;
    int equal_ordering = 0x01;
    int greater_ordering = 0x02;

    /*
     * Reading given public keys from stdin.
     */
    fread(&origin_key, sizeof(origin_key), 1, stdin);
    fread(&alice_key, sizeof(alice_key), 1, stdin);
    fread(&bob_key, sizeof(bob_key), 1, stdin);

    /*
     * Checking the value returned by id_closest();
     * And gives test input: 1-byte TAG + 1-byte ORDERING
     * In order be able to check whether id_closest() working properly or not.
     */
    switch (id_closest(origin_key, alice_key, bob_key)) {
    case 0:
        putchar(success_tag);
        putchar(equal_ordering);
        break;
    case 1:
        putchar(success_tag);
        putchar(less_ordering);
        break;
    case 2:
        putchar(success_tag);
        putchar(greater_ordering);
        break;
    }
}
