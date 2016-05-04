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

/*
 * Packed Node Format
 *
 * MSB bit transport protocol -> UDP=0, TCP=1
 * LSB 7 bit address family -> IPv4=4, IPv6=10
 * 4|16 bytes ip address -> IPv4=4, IPv6=16
 * 2 bytes port number
 * 32 bytes public key -> Node ID
 *
 * The following table is can be used to simplify the implementation.
 * (ip type:transport protocol:address family)
 * 2 (0x02):UDP:IPv4
 * 10 (0x0a):UDP:IPv6
 * 130 (0x82):TCP:IPv4
 * 138 (0x8a):TCP:IPv6
 *
 * more; https://toktok.github.io/spec#node-info-packed-node-format
 *
 */

typedef struct{
    char ip_type;
    unsigned char ip_address[16];
    uint16_t port_number;
    unsigned char public_key[32];
}CNodeInfo;

typedef struct{
    char is_tcp;
    char is_ipv6;
    unsigned char ip_address[16];
    uint16_t port_number;
    unsigned char public_key[32];
}DNodeInfo;



void test_kbucket(void);
void test_distance(void);
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

        char udp_ipv4 = 0x02;
        char udp_ipv6 = 0x0a;
        char tcp_ipv4 = 0x82;
        char tcp_ipv6 = 0x8a;

        DNodeInfo d_node_info;
        fread(&d_node_info.is_tcp, 1, 1, stdin);
        fread(&d_node_info.is_ipv6, 1, 1, stdin);
        if(d_node_info.is_ipv6)
            fread(&d_node_info.ip_address, sizeof d_node_info.ip_address, 1, stdin);
        else
            fread(&d_node_info.ip_address, 4, 1, stdin);
        fread(&d_node_info.port_number, sizeof d_node_info.port_number, 1, stdin);
        fread(&d_node_info.public_key, sizeof d_node_info.public_key, 1, stdin);


        putchar(RESULT_TAG_SUCCESS);
/*
        if(!d_node_info.is_tcp && !d_node_info.is_ipv6)
            putchar(udp_ipv4);
        else if(!d_node_info.is_tcp && d_node_info.is_ipv6)
            putchar(udp_ipv6);
        else if(d_node_info.is_tcp && !d_node_info.is_ipv6)
            putchar(tcp_ipv4);
        else if(d_node_info.is_tcp && d_node_info.is_ipv6)
            putchar(tcp_ipv6);

        if(d_node_info.is_ipv6)
            fwrite(&d_node_info.ip_address, sizeof d_node_info.ip_address, 1, stdout);
        else
            fwrite(&d_node_info.ip_address, 4, 1, stdout);
        fwrite(&d_node_info.port_number, sizeof d_node_info.port_number, 1, stdout);
        fwrite(&d_node_info.public_key, sizeof d_node_info.public_key, 1, stdout);
*/

        IP ip;
        if(!d_node_info.is_tcp && !d_node_info.is_ipv6){
            ip.family = AF_INET; // udp_ipv4;
            memcpy(&ip.ip4.in_addr, d_node_info.ip_address, sizeof d_node_info.ip_address);
        }
        else if(!d_node_info.is_tcp && d_node_info.is_ipv6){
            ip.family = AF_INET6; // udp_ipv6;
            memcpy(&ip.ip6.in6_addr, d_node_info.ip_address, sizeof d_node_info.ip_address);
        }
        else if(d_node_info.is_tcp && !d_node_info.is_ipv6){
            ip.family = TCP_INET; // tcp_ipv4;
            memcpy(&ip.ip4.in_addr, d_node_info.ip_address, sizeof d_node_info.ip_address);
        }
        else if(d_node_info.is_tcp && d_node_info.is_ipv6){
            ip.family = TCP_INET6; // tcp_ipv6;
            memcpy(&ip.ip6.in6_addr, d_node_info.ip_address, sizeof d_node_info.ip_address);
        }


        IP_Port ip_port;
        ip_port.ip = ip;
        ip_port.port = d_node_info.port_number;

        Node_format nodes[1];
        memcpy(nodes[0].public_key, &d_node_info.public_key, sizeof d_node_info.public_key);
        nodes[0].ip_port = ip_port;
        uint8_t data[sizeof nodes]; // is this should be equal to nodes size ?
        int len = pack_nodes(data, sizeof data, nodes, 1);
        fprintf(stderr, "%d\n", len);
        fwrite(data, sizeof data, 1, stdout);
    }
    else if(!memcmp(test_name, BINARY_DECODE_NODEINFO, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_WORD32, len_of_test_name)){
        //word32
        unsigned int word32;
        fread(&word32, sizeof word32, 1, stdin);

        //success tag
        putchar(RESULT_TAG_SUCCESS);
        fwrite(&word32, sizeof word32, 1, stdout);
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
