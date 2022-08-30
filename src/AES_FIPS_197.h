#ifndef _AES_FIPS_197_H
#define _AES_FIPS_197_H

#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept> // DEPRECATED
#include <string>
#include <vector>

enum class AES_standard { AES128, AES192, AES256 };

class AES_FIPS_197
{

public:
	AES_FIPS_197(AES_standard);
	~AES_FIPS_197();

private:
	void initialize(void);

	AES_standard _standard;

	uint8_t Nk;
	uint8_t Nb;
	uint8_t Nr;

	static std::vector<uint8_t> _sbox;
	static std::vector<uint8_t> _invsbox;

	static std::vector<uint8_t> _exp_table;
	static std::vector<uint8_t> _log_table;

	static bool verbose;

	std::vector<std::vector<uint8_t>> _state;

	std::vector<std::vector<uint8_t>> _rcon;

	std::vector<uint8_t> _key;
	std::vector<std::vector<uint8_t>> _keyschedule;
	std::vector<std::vector<uint8_t>> _altkeyschedule;

	std::vector<std::vector<uint8_t>> to_state(const std::vector<uint8_t>&) const;
	std::vector<uint8_t> to_word(const std::vector<std::vector<uint8_t>>&) const;

	uint8_t xtime(const uint8_t &);


	void SubBytes(std::vector<std::vector<uint8_t>>&);
	void ShiftRows(std::vector<std::vector<uint8_t>>&);
	void MixColumns(std::vector<std::vector<uint8_t>>&);

	void SubBytes(void);
	void ShiftRows(void);
	void MixColumns(void);

	void AddRoundKey(const std::vector<std::vector<uint8_t>>&,std::vector<std::vector<uint8_t>>&,uint8_t);

	void AddRoundKey(uint8_t);

	void KeyExpansion(void);
	//void KeyExpansionAddendum(void); // DEPRECATED

	void InvSubBytes(std::vector<std::vector<uint8_t>>&);
	void InvShiftRows(std::vector<std::vector<uint8_t>>&);
	void InvMixColumns(std::vector<std::vector<uint8_t>>&);

	void InvSubBytes(void);
	void InvShiftRows(void);
	void InvMixColumns(void);

	std::vector<uint8_t> SubWord(const std::vector<uint8_t>&) const;
	std::vector<uint8_t> RotWord(const std::vector<uint8_t>&) const;

	std::vector<uint8_t> XorWord(const std::vector<uint8_t>&,const std::vector<uint8_t>&) const;

	void Cipher(void);
	void InvCipher(void);
	//void EqInvCipher(void); // DEPRECATED

	void print_state(const std::vector<std::vector<uint8_t>>&) const;
	void print_word(const std::vector<uint8_t>&) const;

	void print_state(void) const;

	void print_keyschedule_string(const std::vector<std::vector<uint8_t>>&,const uint8_t&) const;
	void print_keyschedule(const std::vector<std::vector<uint8_t>>&) const;

	void print_keyschedule_string(const uint8_t&) const;
	void print_keyschedule(void) const;

	void print_bytetable(const std::vector<uint8_t>&) const;

public:
	std::vector<uint8_t> encrypt(const std::vector<uint8_t>&);
	std::vector<uint8_t> decrypt(const std::vector<uint8_t>&);

	void set_key(const std::vector<uint8_t>&);

	void test_standard(void);

};
#endif
