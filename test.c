/***********************test.h**********************/
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../toxcore/toxcore/DHT.h"
#include <endian.h>

/*https://toktok.github.io/spec#test-names*/
#define DISTANCE                 "Distance"
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

/*https://toktok.github.io/spec#result*/
#define RESULT_TAG_FAILURE       0x00
#define RESULT_TAG_SUCCESS       0x01
#define RESULT_TAG_SKIPPED       0x02

/*https://toktok.github.io/spec#test-distance-3*/
#define ORDERING_LESS            0x00
#define ORDERING_EQUAL           0x01
#define ORDERING_GREATER         0x02

void test_kbucket(void);
void test_distance(void);
void binary_encode_nodeinfo(void);
void binary_encode_word32(void);
void binary_encode_bytestring(void);
void binary_decode_nodeinfo(char *test_name, uint64_t len);
void nonce_increment(void);
/***************************test.h************************/

int main(void)
{
    uint64_t len_of_test_name;
    fread(&len_of_test_name, sizeof len_of_test_name, 1, stdin);
    //len of test name is 64bit encoded in big endian
    len_of_test_name = htobe64(len_of_test_name);

    char test_name[len_of_test_name];
    fread(&test_name, len_of_test_name, 1, stdin);

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
        nonce_increment();
    }
    else if(!memcmp(test_name, BINARY_ENCODE_NODEINFO, len_of_test_name)){
        binary_encode_nodeinfo();
    }
    else if(!memcmp(test_name, BINARY_DECODE_NODEINFO, len_of_test_name)){
        binary_decode_nodeinfo(test_name, len_of_test_name);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_WORD32, len_of_test_name)){
        binary_encode_word32();
    }
    else if(!memcmp(test_name, BINARY_DECODE_WORD32, len_of_test_name)){
  /*      uint32_t word32;
        int len = fread(&word32, 1, sizeof word32, stdin);
        //fprintf(stderr, "%d\n", len);
        if(len == 4){
            putchar(RESULT_TAG_SUCCESS);
            fwrite(&word32, sizeof word32, 1, stdout);
        }else{
            putchar(RESULT_TAG_FAILURE);
            fwrite(&word32, sizeof word32, 1, stdout);
        }
*/
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_STRING, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_DECODE_STRING, len_of_test_name)){
        putchar(RESULT_TAG_SKIPPED);
    }
    else if(!memcmp(test_name, BINARY_ENCODE_BYTESTRING, len_of_test_name)){
        binary_encode_bytestring();
    }
    else if(!memcmp(test_name, TEST_FAILURE, len_of_test_name)){
        putchar(RESULT_TAG_FAILURE);
    }
    else if(!memcmp(test_name, TEST_SUCCESS, len_of_test_name)){
        putchar(RESULT_TAG_SUCCESS);
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
        putchar(strlen(failure_message));
        printf("%s", failure_message);
    }
    return 0;
}


void test_kbucket(void) {
    uint8_t self_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t other_pk[crypto_box_PUBLICKEYBYTES];

    fread(&self_pk, sizeof(self_pk), 1, stdin);
    fread(&other_pk, sizeof(other_pk), 1, stdin);

    putchar(RESULT_TAG_SUCCESS);
    putchar(1);
    putchar(bit_by_bit_cmp(self_pk, other_pk));
}


void test_distance(void){
    uint8_t origin_key[crypto_box_PUBLICKEYBYTES];
    uint8_t alice_key[crypto_box_PUBLICKEYBYTES];
    uint8_t bob_key[crypto_box_PUBLICKEYBYTES];

    fread(&origin_key, sizeof(origin_key), 1, stdin);
    fread(&alice_key, sizeof(alice_key), 1, stdin);
    fread(&bob_key, sizeof(bob_key), 1, stdin);

    switch (id_closest(origin_key, alice_key, bob_key)) {
    case 0:
        putchar(RESULT_TAG_SUCCESS);
        putchar(ORDERING_EQUAL);
        break;
    case 1:
        putchar(RESULT_TAG_SUCCESS);
        putchar(ORDERING_LESS);
        break;
    case 2:
        putchar(RESULT_TAG_SUCCESS);
        putchar(ORDERING_GREATER);
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
        fread(&nodes[0].ip_port.ip.ip6, SIZE_IP6, 1, stdin);
        if(is_tcp)
            nodes[0].ip_port.ip.family = TCP_INET6;
        else
            nodes[0].ip_port.ip.family = AF_INET6;
    }
    else{
        fread(&nodes[0].ip_port.ip.ip4, SIZE_IP4, 1, stdin);
        if(is_tcp)
            nodes[0].ip_port.ip.family = TCP_INET;
        else
            nodes[0].ip_port.ip.family = AF_INET;
    }
    fread(&nodes[0].ip_port.port, sizeof(uint16_t), 1, stdin);
    fread(&nodes[0].public_key, crypto_box_PUBLICKEYBYTES, 1, stdin);

    int size = !is_ipv6
        ? SIZE_IP4 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES + 1
        : SIZE_IP6 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES + 1;
    uint8_t data[size];
    pack_nodes(data, sizeof data, nodes, 1);
    putchar(RESULT_TAG_SUCCESS);
    fwrite(data, sizeof data, 1, stdout);
}

void binary_decode_nodeinfo(char *test_name, uint64_t len){
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

    int num = unpack_nodes(nodes, 1, &processed_data_len, data, sizeof data, tcp_enabled);

    if(num > 0){
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
    else{
        putchar(RESULT_TAG_FAILURE);
        //prefixed-length of error message
        for (int i = 0; i < 7; i++) {
            putchar(0);
        }
        putchar(len);
        printf("%s", test_name);
    }
}

void binary_encode_word32(void){
    uint32_t word32;
    fread(&word32, sizeof word32, 1, stdin);

    putchar(RESULT_TAG_SUCCESS);
    fwrite(&word32, sizeof word32, 1, stdout);
}

void binary_encode_bytestring(void){
    uint64_t bencode_len_of_list;
    fread(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdin);
    //len of bencode_bytestring is 64bit encoded in big endian
    bencode_len_of_list = htobe64(bencode_len_of_list);

    char bencode_bytestring[bencode_len_of_list];
    fread(&bencode_bytestring, bencode_len_of_list, 1, stdin);
    bencode_len_of_list = be64toh(bencode_len_of_list);

    putchar(RESULT_TAG_SUCCESS);
    fwrite(&bencode_len_of_list, sizeof bencode_len_of_list, 1, stdout);
    fwrite(&bencode_bytestring, sizeof bencode_bytestring, 1, stdout);
}

void nonce_increment(void){
    uint8_t nonce[24];
    fread(&nonce, sizeof nonce, 1, stdin);
    increment_nonce(nonce);

    putchar(RESULT_TAG_SUCCESS);
    fwrite(&nonce, sizeof nonce , 1, stdout);
}
