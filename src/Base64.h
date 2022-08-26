#ifndef BASE64_H
#define BASE64_H

#include <vector>
#include <string>

class Base64 {
  public:
  static const std::string STD_CHARSET; // Base64 standard charset
  static const std::string URL_CHARSET; // Base64 URL safe charset

  static bool decode(const std::string*, std::string*, const std::string *charset = &Base64::STD_CHARSET);       // Decode string from Base64
  static bool decode(const std::string*, std::vector<char>*, const std::string *charset = &Base64::STD_CHARSET); // Decode vector from Base64

  static void encode(const std::string*, std::string*, const std::string *charset = &Base64::STD_CHARSET, const bool padding = true);       // Encode string to Base64
  static void encode(const std::vector<char>*, std::string*, const std::string *charset = &Base64::STD_CHARSET, const bool padding = true); // Encode vector to Base64

  static bool is_standard(const std::string*); // Check if the encoded string respects the standard charset.
  static bool is_url_safe(const std::string*); // Check if the encoded string respects the URL safe charset.

  private:
  // Base64 core
  static bool decode(const char*, const unsigned long, char*, const std::string*);                            // Decode from Base64
  static void encode(const char*, const unsigned long, std::string*, const std::string*, const bool padding); // Encode to Base64

  // Respect the charset?
  static bool is_base64(const std::string*, const std::string*); // Check if the encoded string respect the given charset.
  static inline bool is_valid_char(char, const std::string*);    // Check if the char respect the given charset.

  // Predict the length of result
  static inline unsigned long predict_enc_len(const unsigned long, const bool); // Predict the length of encoded data
  static inline unsigned long predict_dec_len(const std::string*);              // Predict the length of decoded data
};

#endif
