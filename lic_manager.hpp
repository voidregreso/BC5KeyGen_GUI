#pragma once
#include <string>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>

const std::string PUBLIC_KEY = "++11Ik:7EFlNLs6Yqc3p-LtUOXBElimekQm8e3BTSeGhxhlpmVDeVVrrUAkLTXpZ7mK6jAPAOhyHiokPtYfmokklPELfOxt1s5HJmAnl-5r8YEvsQXY8-dm6EFwYJlXgWOCutNn2+FsvA7EXvM-2xZ1MW8LiGeYuXCA6Yt2wTuU4YWM+ZUBkIGEs1QRNRYIeGB9GB9YsS8U2-Z3uunZPgnA5pF+E8BRwYz9ZE--VFeKCPamspG7tdvjA3AJNRNrCVmJvwq5SqgEQwINdcmwwjmc4JetVK76og5A5sPOIXSwOjlYK+Sm8rvlJZoxh0XFfyioHz48JV3vXbBKjgAlPAc7Npn+wk"; 
const std::string PRIVATE_KEY = "4860d32b474ff398b0058aaf111fe820f8bebad4342cb40b6fd7652b37a92cf077d58ca7374dcf65615fe846e73ababe6a729a59ebdd8b980bbeb47f3ef8041decc465118a40d76293b5fce1271d87865b3f1dc116f2637d8dfa338a5103ef14e9c28f620c325c1e241e2bfa9258d16b1239c5c06ce13ec2fe377fac038a0ff0eb0f5910018724fd4bf429f1c0fac86af083acdab388c18e281a5ea9976b385e6c0383485135f1e68cd7a3c0ab6d36b07aa1404e081083158e523129ace077972fc3bd9424fbe86c64b33e8916e0a15c0f5a346e2260fb565ee00741268e6987b978df646c81bd72b55e0ea94f5f51956bf80ffc4c51f6fcaaab96135c888523";

class LicType {
public:
    static const uint8_t WINDOWS = 4;
    static const uint8_t LINUX = 8;
    static const uint8_t MACOS = 0x10;
    static const uint8_t PRO = 0x21;
    static const uint8_t ALL = WINDOWS | LINUX | MACOS | PRO;
};

class LicenseEncoder {
public:
    LicenseEncoder(const std::string& username, const std::string& atsite, 
                  int user_num, const std::string& serial_num, uint8_t lic_type = LicType::ALL);
    std::string encode();

private:
    std::string username;
    std::string atsite;
    int user_num;
    std::string serial_num;
    uint8_t license_type;
    
    std::vector<uint8_t> gen_lic();
    static std::vector<uint8_t> gen_padding_lic(const std::vector<uint8_t>& data);
};

class LicenseDecoder {
public:
    explicit LicenseDecoder(const std::string& lic_key);
    std::tuple<int, std::string, std::string, std::string, std::string, std::string> decode();

private:
    std::vector<uint8_t> data;
    std::tuple<int, std::string> dec_org();
    std::string dec_version();
    std::tuple<std::string, std::string> dec_random();
    std::string dec_uname();
};

std::vector<uint8_t> base64_decode_ext(const std::vector<uint8_t>& input);
std::vector<uint8_t> reverse_by_word(const std::vector<uint8_t>& data);
std::vector<uint8_t> int_to_bytes(const CryptoPP::Integer& n);
std::tuple<CryptoPP::Integer, CryptoPP::Integer, CryptoPP::Integer> get_rsa_key_info();
CryptoPP::Integer rsa_encrypt_decrypt(const CryptoPP::Integer& data, 
                                    const CryptoPP::Integer& exp, 
                                    const CryptoPP::Integer& mod);