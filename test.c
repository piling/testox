/***********************test.h**********************/
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../toxcore/toxcore/DHT.h"
#include <endian.h>


//Test Names

/*
 * Distance Test
 *
 * Checks whether the xor-distance metric works correctly.
 *
 * Input:(length:type:contents)
 * 8:Int:Length of name
 * 8:Message Kind:Test name: "Distance"
 * 32:Public Key:Origin key
 * 32:Public Key:Alice key
 * 32:Public Key:Bob key
 *
 * Output:(lenght:type:contents)
 * 1:Tag:0x01 (Success)
 * 1:Ordering:Less, Equal, or Greater
 *
 * Ordering:(value:encoding:when)
 * Less:0x00:distance(Origin, Alice) < distance(Origin, Bob)
 * Equal:0x01:the distances are equal
 * Greater:0x02:distance(Origin, Alice) > distance(Origin, Bob).
 *
 */
#define DISTANCE                 "Distance"

/*
 * K-Bucket Index Test
 *
 * Checks whether the K-bucket index is computed correctly.
 *
 * Input: Two public keys for Self and Other. (length:type:contents)
 * 8:Int:Length of name
 * 12:Message Kind:Test name: "KBucketIndex"
 * 32:Public Key:Base key
 * 32:Public Key:Node key
 *
 * Output: either Nothing or Just i in a Success(success tag + payload) message.
 * 1:0x00:Base key == Node key: Nothing
 * 2:0x01, i:otherwise: Just i
 * The value of i is the k-bucket index of the Node key in a k-buckets
 * instance with the given Base key.
 *
 */
#define K_BUCKET_INDEX           "KBucketIndex"

#define K_BUCKET_NODES           "KBucketNodes"
#define NONCE_INCREMENT          "NonceIncrement"

#define BINARY_ENCODE_NODEINFO   "BinaryEncode NodeInfo"
#define BINARY_ENCODE_STRING     "BinaryEncode String"
#define BINARY_ENCODE_BYTESTRING "BinaryEncode ByteString"
#define BINARY_ENCODE_WORD32     "BinaryEncode Word32"

#define BINARY_DECODE_NODEINFO   "BinaryDecode NodeInfo"
#define BINARY_DECODE_STRING     "BinaryDecode String"
#define BINARY_DECODE_WORD32     "BinaryDecode Word32"

#define TEST_FAILURE             "Failuretest"
#define TEST_SUCCESS             "SuccessTest"
#define TEST_SKIPPED             "SkippedTest"

/*
 * The Result type is written to stdout. It is a single byte
 * for Failure (0x00), Success (0x01), and Skipped (0x02),
 * followed by the result data.
 * more; https://toktok.github.io/spec#result
 *
 */

#define RESULT_TAG_FAILURE       0x00
#define RESULT_TAG_SUCCESS       0x01
#define RESULT_TAG_SKIPPED       0x02


void test_kbucket(void);
void test_distance(void);
void binary_encode_nodeinfo(void);
void binary_encode_word32(void);
void binary_encode_bytestring(void);
void binary_decode_nodeinfo(void);
/***************************test.h************************/

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
    else if(!memcmp(test_name, K_BUCKET_NODES, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, NONCE_INCREMENT, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_NODEINFO, len_of_test_name)){
        binary_encode_nodeinfo();
    }
    else if(!memcmp(test_name, BINARY_DECODE_NODEINFO, len_of_test_name)){
        binary_decode_nodeinfo();
    }
    else if(!memcmp(test_name, BINARY_ENCODE_WORD32, len_of_test_name)){
        binary_encode_word32();
    }
    else if(!memcmp(test_name, BINARY_DECODE_WORD32, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_STRING, len_of_test_name)){
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
    else if(!memcmp(test_name, BINARY_DECODE_STRING, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_BYTESTRING, len_of_test_name)){
        binary_encode_bytestring();
    }
    else if(!memcmp(test_name, TEST_FAILURE, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, TEST_SUCCESS, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, TEST_SKIPPED, len_of_test_name)){
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

void binary_encode_nodeinfo(void){
    Node_format nodes[1];
    char is_tcp;
    char is_ipv6;
    fread(&is_tcp, 1, 1, stdin);
    fread(&is_ipv6, 1, 1, stdin);
    if(is_ipv6){
        fread(&nodes[0].ip_port.ip.ip6, 16, 1, stdin);
        if(is_tcp)
            nodes[0].ip_port.ip.family = TCP_INET6;
        else
            nodes[0].ip_port.ip.family = AF_INET6;
    }
    else{
        fread(&nodes[0].ip_port.ip.ip4, 4, 1, stdin);
        if(is_tcp)
            nodes[0].ip_port.ip.family = TCP_INET;
        else
            nodes[0].ip_port.ip.family = AF_INET;
    }
    fread(&nodes[0].ip_port.port, 2, 1, stdin);
    fread(&nodes[0].public_key, 32, 1, stdin);

    int size = !is_ipv6
        ? SIZE_IP4 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES + 1
        : SIZE_IP6 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES + 1;
    uint8_t data[size];
    pack_nodes(data, sizeof data, nodes, 1);
    putchar(RESULT_TAG_SUCCESS);
    fwrite(data, sizeof data, 1, stdout);
}

void binary_decode_nodeinfo(void){
    uint64_t size;
    fread(&size, sizeof size, 1, stdin);
    size = htobe64(size);

    uint8_t data[size];
    fread(&data, size, 1, stdin);

    Node_format nodes[1];
    uint16_t processed_data_len;
    uint8_t tcp_enabled = data[0] == TOX_TCP_INET || data[0] == TOX_TCP_INET6
        ? 0x01
        : 0x00;

    unpack_nodes(nodes, 1, &processed_data_len, data, sizeof data, tcp_enabled);

    putchar(RESULT_TAG_SUCCESS);
    //is tcp
    nodes[0].ip_port.ip.family == TCP_INET || nodes[0].ip_port.ip.family == TCP_INET6
        ? putchar(1)
        : putchar(0);
    //is ipv6
    nodes[0].ip_port.ip.family == TCP_INET6 || nodes[0].ip_port.ip.family == AF_INET6
        ? putchar(1)
        : putchar(0);
    //ip addr
    nodes[0].ip_port.ip.family == TCP_INET || nodes[0].ip_port.ip.family == AF_INET
        ? fwrite(&nodes[0].ip_port.ip.ip4, sizeof nodes[0].ip_port.ip.ip4, 1, stdout)
        : fwrite(&nodes[0].ip_port.ip.ip6, sizeof nodes[0].ip_port.ip.ip6 , 1, stdout);

    fwrite(&nodes[0].ip_port.port, sizeof nodes[0].ip_port.port, 1, stdout);
    fwrite(&nodes[0].public_key, sizeof nodes[0].public_key, 1, stdout);
}

void binary_encode_word32(void){
    //word32
    unsigned int word32;
    fread(&word32, sizeof word32, 1, stdin);

    //success tag
    putchar(RESULT_TAG_SUCCESS);
    fwrite(&word32, sizeof word32, 1, stdout);
}

void binary_encode_bytestring(void){
    uint64_t bencode_len_of_list;
    // Reading 64 bit length of list
    fread(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdin);
    bencode_len_of_list = htobe64(bencode_len_of_list);
    char bencode_bytestring[bencode_len_of_list];
    fread(&bencode_bytestring, bencode_len_of_list, 1, stdin);

    bencode_len_of_list = be64toh(bencode_len_of_list);
    putchar(RESULT_TAG_SUCCESS);
    fwrite(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdout);
    fwrite(&bencode_bytestring, sizeof bencode_bytestring, 1, stdout);
}
