#include "Base64.h"

////////////
// PUBLIC //
////////////

// Standard charset
const std::string Base64::STD_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// URL safe charset
const std::string Base64::URL_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Decode string from Base64
bool Base64::decode(const std::string *enc, std::string *dec, const std::string *charset) {
  dec->resize(Base64::predict_dec_len(enc));
  return Base64::decode(&((*enc)[0]), enc->size(), &((*dec)[0]), charset);
}

// Decode binary from Base64
bool Base64::decode(const std::string *enc, std::vector<char> *dec, const std::string *charset) {
  dec->resize(Base64::predict_dec_len(enc));
  return Base64::decode(&((*enc)[0]), enc->size(), &((*dec)[0]), charset);
}

// Encode string to Base64
void Base64::encode(const std::string *txt, std::string *enc, const std::string *charset, const bool padding) {
  enc->clear();
  Base64::encode(&((*txt)[0]), txt->size(), enc, charset, padding);
}

// Encode binary to Base64
void Base64::encode(const std::vector<char> *bin, std::string *enc, const std::string *charset, const bool padding) {
  enc->clear();
  Base64::encode(&((*bin)[0]), bin->size(), enc, charset, padding);
}

// Check if the encoded string respects the standard charset.
bool Base64::is_standard(const std::string *enc) {
  return Base64::is_base64(enc, &Base64::STD_CHARSET);
}

// Check if the encoded string respects the URL safe charset.
bool Base64::is_url_safe(const std::string *enc) {
  return Base64::is_base64(enc, &Base64::URL_CHARSET);
}

/////////////
// PRIVATE //
/////////////

// Decode chars from Base64
bool Base64::decode(const char *enc, const unsigned long enc_len, char *dec, const std::string *charset) {
  char buffer[4];
  unsigned short block = 0;
  unsigned long dec_len = 0;
  for (unsigned long i=0; i<enc_len; i++) {
    if (! Base64::is_valid_char(enc[i], charset)) return false;
    buffer[block++] = charset->find(enc[i]);
    switch (block) {
      case 2:
        dec[dec_len++] = ((buffer[0] & 0b00111111) << 2) | ((buffer[1] & 0b00110000) >> 4);
        break;
      case 3:
        dec[dec_len++] = ((buffer[1] & 0b00001111) << 4) | ((buffer[2] & 0b00111100) >> 2);
        break;
      case 4:
        block = 0;
        dec[dec_len++] = ((buffer[2] & 0b00000011) << 6) | (buffer[3] & 0b00111111);
        break;
    }
  }
  return true;
}

// Encode chars to Base64
void Base64::encode(const char *src, const unsigned long src_len, std::string *enc, const std::string *charset, const bool padding) {
  // Reserve space
  enc->reserve(Base64::predict_enc_len(src_len, padding));

  // Encode a block every 3 bytes
  unsigned short block = 0;
  for (unsigned long i=0; i<src_len; i++) {
    if (++block == 3) {
      block = 0;
      enc->push_back((*charset)[ (src[i-2] >> 2) & 0b111111 ]);
      enc->push_back((*charset)[ ((src[i-2] << 4) | (src[i-1] >> 4)) & 0b111111 ]);
      enc->push_back((*charset)[ ((src[i-1] << 2) | (src[i] >> 6)) & 0b111111 ]);
      enc->push_back((*charset)[ src[i] & 0b111111 ]);
    }
  }

  // Encode last incomplete block
  if (block > 0) { // Some bytes left
    enc->push_back((*charset)[ (src[src_len-block] >> 2) & 0b111111 ]);
    if (block == 1) { // 2 bytes left
      enc->push_back((*charset)[ (src[src_len-block] << 4) & 0b111111 ]);
      if (padding) enc->push_back('=');
    }
    else { // 1 byte left
      enc->push_back((*charset)[ ((src[src_len-block] << 4) | (src[src_len-1] >> 4)) & 0b111111 ]);
      enc->push_back((*charset)[ (src[src_len-1] << 2) & 0b111111 ]);
    }
    if (padding) enc->push_back('=');
  }
}

// Check if the encoded string respect the given charset.
bool Base64::is_base64(const std::string *enc, const std::string *charset) {
  unsigned long last_i = enc->find_last_not_of('=');
  if (last_i == std::string::npos) return false;

  for (unsigned long i=0; i<=last_i; i++) {
    if (! Base64::is_valid_char((*enc)[i], charset)) return false;
  }
  return true;
}

// Check if the char respect the given charset.
inline bool Base64::is_valid_char(char c, const std::string *charset) {
  return (isalnum(c) || (c == (*charset)[62]) || (c == (*charset)[63]));
}

// Predict encode length
inline unsigned long Base64::predict_enc_len(const long unsigned int src_len, const bool padding) {
  unsigned long blk_mod = src_len % 3;
  unsigned long enc_len = (((src_len - blk_mod) / 3) * 4);
  if (blk_mod > 0) {
    if (padding) enc_len+=4;
    else {
      if (blk_mod == 1) enc_len+=2;
      if (blk_mod == 2) enc_len+=3;
    }
  }
  return enc_len;
}

// Predict decode length
inline unsigned long Base64::predict_dec_len(const std::string *enc) {
  unsigned long enc_len = enc->find_last_not_of('=')+1;
  if (enc_len == std::string::npos) return 0;
  unsigned long blk_mod = enc_len % 4;
  unsigned long dec_len = (((enc_len - blk_mod) / 4) * 3);
  if (blk_mod > 0) dec_len+=blk_mod-1;
  return dec_len;
}
