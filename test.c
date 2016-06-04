#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../toxcore/toxcore/DHT.h"
#include <endian.h>

/*https://toktok.github.io/spec#result*/
#define RESULT_TAG_FAILURE       0x00
#define RESULT_TAG_SUCCESS       0x01
#define RESULT_TAG_SKIPPED       0x02

/*https://toktok.github.io/spec#test-distance-3*/
#define ORDERING_LESS            0x00
#define ORDERING_EQUAL           0x01
#define ORDERING_GREATER         0x02

#define MAX_CMD_LENGTH 512
/** struct to look through all tests. */
typedef struct TESTS {
    const char *test;
    void  (*function)(int argc, char (*argv)[MAX_CMD_LENGTH]);
} TESTS;

/*https://toktok.github.io/spec#test-names*/
void test_distance(int argc, char (*argv)[MAX_CMD_LENGTH]);

void test_kbucket(int argc, char (*argv)[MAX_CMD_LENGTH]);
void test_kbucket_nodes(int argc, char (*argv)[MAX_CMD_LENGTH]);

void nonce_increment(int argc, char (*argv)[MAX_CMD_LENGTH]);

void binary_encode_nodeinfo(int argc, char (*argv)[MAX_CMD_LENGTH]);
void binary_decode_nodeinfo(int argc, char (*argv)[MAX_CMD_LENGTH]);

void binary_encode_word32(int argc, char (*argv)[MAX_CMD_LENGTH]);
void binary_decode_word32(int argc, char (*argv)[MAX_CMD_LENGTH]);

void binary_encode_bytestring(int argc, char (*argv)[MAX_CMD_LENGTH]);

void binary_encode_string(int argc, char (*argv)[MAX_CMD_LENGTH]);
void binary_decode_string(int argc, char (*argv)[MAX_CMD_LENGTH]);

void test_failure(int argc, char (*argv)[MAX_CMD_LENGTH]);
void test_success(int argc, char (*argv)[MAX_CMD_LENGTH]);
void test_skipped(int argc, char (*argv)[MAX_CMD_LENGTH]);

/** List of tests we support */
TESTS tests[] = {
    {"Distance",                       test_distance               },
    {"KBucketIndex",                   test_kbucket                },
    {"KBucketNodes",                   test_kbucket_nodes          },
    {"NonceIncrement",                 nonce_increment             },
    {"BinaryEncode NodeInfo",          binary_encode_nodeinfo      },
    {"BinaryDecode NodeInfo",          binary_decode_nodeinfo      },
    {"BinaryEncode Word32",            binary_encode_word32        },
    {"BinaryDecode Word32",            binary_decode_word32        },
    {"BinaryEncode ByteString",        binary_encode_bytestring    },
    {"BinaryEncode String",            binary_encode_string        },
    {"BinaryDecode String",            binary_decode_string        },
    {"SuccessTest",                    test_success                },
    {"Failuretest",                    test_failure                },
    {"SkippedTest",                    test_skipped                },
    {NULL,                             NULL                        },
};




int main(void){
    uint64_t len_of_test_name;
    fread(&len_of_test_name, sizeof len_of_test_name, 1, stdin);
    //len of test name is 64bit encoded in big endian
    len_of_test_name = htobe64(len_of_test_name);

    char test_name[len_of_test_name];
    fread(&test_name, len_of_test_name, 1, stdin);

    uint test_number = 0;
    while (tests[test_number].test) {
        if (memcmp(test_name, tests[test_number].test, len_of_test_name) == 0) {
            /* We don't pass anything to functions yet, so 0, NULL is ugly but correct. */
            (tests[test_number].function)(0, NULL);
        }
        test_number++;
    }

    return 0;
}


void test_distance(int argc, char (*argv)[MAX_CMD_LENGTH]) {
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

void test_kbucket(int argc, char (*argv)[MAX_CMD_LENGTH]) {
    uint8_t self_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t other_pk[crypto_box_PUBLICKEYBYTES];

    fread(&self_pk, sizeof(self_pk), 1, stdin);
    fread(&other_pk, sizeof(other_pk), 1, stdin);

    putchar(RESULT_TAG_SUCCESS);
    putchar(1);
    putchar(bit_by_bit_cmp(self_pk, other_pk));
}

void test_kbucket_nodes(int argc, char (*argv)[MAX_CMD_LENGTH]){
    uint64_t bucket_size;
    uint8_t base_key[crypto_box_PUBLICKEYBYTES];

    fread(&bucket_size, sizeof bucket_size, 1, stdin);
    bucket_size = htobe64(bucket_size);
    fread(&base_key, crypto_box_PUBLICKEYBYTES, 1, stdin);

    Node_format nodes[bucket_size];

    for(int i = 0; i < bucket_size; i++){
        char is_tcp;
        char is_ipv6;

        fread(&is_tcp, 1, 1, stdin);
        fread(&is_ipv6, 1, 1, stdin);

        if(is_ipv6){
            fread(&nodes[i].ip_port.ip.ip6, SIZE_IP6, 1, stdin);
            if(is_tcp)
                nodes[i].ip_port.ip.family = TCP_INET6;
            else
                nodes[i].ip_port.ip.family = AF_INET6;
        }
        else{
            fread(&nodes[i].ip_port.ip.ip4, SIZE_IP4, 1, stdin);
            if(is_tcp)
                nodes[i].ip_port.ip.family = TCP_INET;
            else
                nodes[i].ip_port.ip.family = AF_INET;
        }
        fread(&nodes[i].ip_port.port, sizeof(uint16_t), 1, stdin);
        fread(&nodes[i].public_key, crypto_box_PUBLICKEYBYTES, 1, stdin);
    }

    uint8_t *keys[bucket_size];
    for(int i = 0; i< bucket_size; i++){
        fread(&keys[i], crypto_box_PUBLICKEYBYTES, 1, stdin);
    }

}

void nonce_increment(int argc, char (*argv)[MAX_CMD_LENGTH]){
    uint8_t nonce[24];
    fread(&nonce, sizeof nonce, 1, stdin);
    increment_nonce(nonce);

    putchar(RESULT_TAG_SUCCESS);
    fwrite(&nonce, sizeof nonce , 1, stdout);
}

void binary_encode_nodeinfo(int argc, char (*argv)[MAX_CMD_LENGTH]){
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

void binary_decode_nodeinfo(int argc, char (*argv)[MAX_CMD_LENGTH]){
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
        putchar(0x15);
        char test_name[] = "BinaryDecode NodeInfo";
        printf("%s", test_name);
    }
}

void binary_encode_word32(int argc, char (*argv)[MAX_CMD_LENGTH]){
    uint32_t word32;
    fread(&word32, sizeof word32, 1, stdin);

    putchar(RESULT_TAG_SUCCESS);
    fwrite(&word32, sizeof word32, 1, stdout);
}

void binary_decode_word32(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}

void binary_encode_bytestring(int argc, char (*argv)[MAX_CMD_LENGTH]){
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

void binary_encode_string(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}

void binary_decode_string(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}

void test_success(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}

void test_failure(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}

void test_skipped(int argc, char (*argv)[MAX_CMD_LENGTH]){
    putchar(RESULT_TAG_SKIPPED);
}
