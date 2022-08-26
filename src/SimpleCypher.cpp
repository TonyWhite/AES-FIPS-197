#include "Base64.h"
#include "SimpleCypher.h"
#include <chrono>
#include <iostream>
#include <random>

void SimpleCypher::encrypt(const std::string *data, const std::string *password, std::string *encrypted) {
  std::cout << "SimpleCypher::encrypt" << std::endl;
  std::vector<char> padded;
  SimpleCypher::padding(data, &padded);
  std::cout << "  " << "padding data: OK" << std::endl;
  std::string unpadded;
  SimpleCypher::unpadding(&padded, &unpadded);
  char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}; //key example
}

char SimpleCypher::randomByte() {
  std::uniform_int_distribution<int> distribution(0,255);                      // Define uniform distribution from 0 to 255
  unsigned seed = std::chrono::system_clock::now().time_since_epoch().count(); // Change seed every time
  std::default_random_engine generator(seed);                                  // Reset engine every time
  return distribution(generator);                                              // Return random byte
}

/////////////
// PRIVATE //
/////////////

// Padding string to buffer
/*
Padding:
1- sizeof(secret) must be divisible by 16
  1.1- filling  the remaining bytes with 0x00. Limit: data that ends with 0x00 and filled up with 0x00 can't be recognized correctly
  1.2- base64 of secret, then sizeof(secret_b64) must be divisible by 16
    1.2.1- filling the remaining bytes with 0x00. data is recognized correctly
    1.2.2- decrypt data, remove trailing 0x00 bytes, decode from base64. Here is the original data!
  1.3- filling  the remaining with random bytes. The last byte is a Control Byte.
    1.3.1- filling the remaining bytes with random values. The last byte indicates how much bytes are added.
    1.3.2- decrypt data, remove added bytes. Here is the original data!
  1.4- filling the remaining with pseudo-random bytes. The last byte is a Control Byte.
    1.4.1- filling the remaining bytes with pseudo-random values.
      1.4.1.1- seed of pseudo-random is taken from secret's bytes.
      1.4.1.2- The last byte is a Control Byte
    1.4.2- decrypt data, remove added bytes. Here is the original data!
Solution 1.2:
secret -> base64 -> add trailing 0x00 to be divisible by 16 -> encrypt -> base64 -> encrypted data
encrypted data -> decode from base64 -> decrypt -> remove trailing 0x00 -> decode from base64 -> secret
Solution 1.3:
secret -> fill last block | add block -> encrypt -> base64 -> encrypted data
encrypted data -> decode from base64 -> decrypt -> remove filling -> secret
Solution 1.4:
secret -> fill last block | add block -> encrypt -> base64 -> encrypted data
encrypted data -> decode from base64 -> decrypt -> remove filling -> secret
The best solution is 1.4:
- Less CPU time
- Less RAM usage
- Encoding the data with the same key will always give the same result. It is useful to ensure zero-knowledge from server.
*/
void SimpleCypher::padding(const std::string *data, std::vector<char> *buffer) {
  char controlByte = 16 - data->size() % 16;

  // Buffer starts with pseudo-random bytes
  // Take seed from data:
  // it is useful to ensure zero-knowledge from server.
  std::uniform_int_distribution<int> distribution(0,255);
  std::seed_seq seed (data->begin(), data->end());
  std::default_random_engine generator(seed);
  for (uint8_t i=1; i<controlByte; i++)
    buffer->push_back(distribution(generator));

  // Append data to buffer
  for (unsigned long i=0; i<data->size(); i++)
    buffer->push_back((char)data->at(i));

  // Append control byte to buffer
  buffer->push_back(controlByte);
}

void SimpleCypher::unpadding(const std::vector<char> *buffer, std::string *unpadded) {
  char controlByte = buffer->back();
  *unpadded = "";
  for (unsigned int i=controlByte-1; i<buffer->size()-1; i++) {
    unpadded->push_back(buffer->at(i));
  }
}
