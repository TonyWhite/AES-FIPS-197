/*
SIMPLE ENCRYPT/DECRYPT
Auto padding data
Force standard using AES 256 bit
IV from key
*/

#ifndef SIMPLE_CYPHER_H
#define SIMPLE_CYPHER_H

#include <string>
#include <vector>

class SimpleCypher {
  public:
    // String
    static void encrypt(const std::string *data, const std::string *password, std::string *encrypted);
    static void decrypt(const std::string *data, const std::string *password, std::string *decrypted);

    // Vector
    static void encrypt(std::vector<char> *data);
    static void decrypt(std::vector<char> *data);

    // Static array
    static void encrypt();
    static void decrypt();

    // Get a random byte
    static char randomByte();

    // Password generator
    //static void genPassword();

  private:
    // Padding string to buffer
    static void padding(const std::string *data, std::vector<char> *buffer);

    // Unpadding string from buffer
    static void unpadding(const std::vector<char> *buffer, std::string *data);
};

#endif
