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
