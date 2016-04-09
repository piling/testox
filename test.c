#include "test.h"

int main(void)
{
    uint64_t len_of_test_name;
    // Reading 64 bit integer len of test name(e.g. Distance) from stdin.
    fread(&len_of_test_name, sizeof len_of_test_name, 1, stdin);
    // swapping endiannes and returning len of test name
    len_of_test_name = htobe64(len_of_test_name);

    char test_name[len_of_test_name];
     // reading str of test name
    fread(&test_name, len_of_test_name, 1, stdin);

    // Determines which test case is given
    if(!memcmp(test_name, DISTANCE, len_of_test_name)){
        test_distance();
    }
    else if(!memcmp(test_name, K_BUCKET_INDEX, len_of_test_name)){
        test_kbucket();
    }
    else if(!memcmp(test_name, "KBucketNodes", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "NonceIncrement", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "BinaryEncode NodeInfo", len_of_test_name)){
        NodeInfo node_info;
        fread(&node_info.ip_type, 1, 1, stdin);
        fread(&node_info.ip_address, sizeof node_info.ip_address, 1, stdin);
        fread(&node_info.port, sizeof node_info.port, 1, stdin);
        fread(&node_info.public_key, sizeof node_info.public_key, 1, stdin);

        putchar(RESULT_TAG_SUCCESS);
        fwrite(&node_info.ip_type, 1, 1, stdout);
        fwrite(&node_info.ip_address, sizeof node_info.ip_address, 1, stdout);
        fwrite(&node_info.port, sizeof node_info.port, 1, stdout);
        fwrite(&node_info.public_key, sizeof node_info.public_key, 1, stdout);
    }
    else if(!memcmp(test_name, "BinaryDecode NodeInfo", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "BinaryEncode Word32", len_of_test_name)){
        //word32
        unsigned int word32;
        fread(&word32, sizeof word32, 1, stdin);

        //success tag
        putchar(RESULT_TAG_SUCCESS);
        fwrite(&word32, sizeof word32, 1, stdout);
    }
    else if(!memcmp(test_name, "BinaryDecode Word32", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "BinaryEncode String", len_of_test_name)){
/*
        uint64_t bencode_len_of_list;
        // Reading 64 bit length of list
        fread(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdin);
        bencode_len_of_list = htobe64(bencode_len_of_list);
        char bencode_string[bencode_len_of_list];
        fread(&bencode_string, bencode_len_of_list, 1, stdin);

        bencode_len_of_list = be64toh(bencode_len_of_list);
        putchar(RESULT_TAG_SUCCESS);
        fwrite(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdout);
        fwrite(&bencode_string, sizeof bencode_string, 1, stdout);
*/
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "BinaryDecode String", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "FailureTest", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "SuccessTest", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, "SkippedTest", len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else{
        //error message
        char failure_message[] = "Unhandled test:";
        strncat(failure_message, test_name,strlen(test_name)+1);

        putchar(RESULT_TAG_FAILURE);
        //prefixed-length of error message
        for (int i = 0; i < 7; i++) {
            putchar(0);
        }
        //char *prefix_length = "\x00\x00\x00\x00\x00\x00\x00";
        //fwrite(prefix_length, sizeof prefix_length, 1, stdout);
        putchar(strlen(failure_message));
        printf("%s", failure_message);
    }
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
        putchar(RESULT_TAG_SUCCESS);
        putchar(equal_ordering);
        break;
    case 1:
        putchar(RESULT_TAG_SUCCESS);
        putchar(less_ordering);
        break;
    case 2:
        putchar(RESULT_TAG_SUCCESS);
        putchar(greater_ordering);
        break;
    }
}
