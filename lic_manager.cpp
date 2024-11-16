#include "lic_manager.hpp"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include "libbase58.h"

const std::vector<uint8_t> STANDARD_ALPHABET = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'};

const std::vector<uint8_t> CUSTOM_ALPHABET = {'+','-','0','1','2','3','4','5','6','7','8','9','A','B','C','D',
    'E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d',
    'e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};

std::vector<uint8_t> base64_decode_ext(const std::vector<uint8_t>& input) {
    std::string decoded;
    CryptoPP::Base64Decoder decoder;
    
    // Crear tabla de traducción
    unsigned char trans[256];
    std::fill_n(trans, 256, 0);
    for(size_t i = 0; i < CUSTOM_ALPHABET.size(); ++i) {
        trans[CUSTOM_ALPHABET[i]] = STANDARD_ALPHABET[i];
    }
    
    // Traducir entrada
    std::vector<uint8_t> translated;
    translated.reserve(input.size());
    for(uint8_t c : input) {
        translated.push_back(trans[c]);
    }
    
    // Añadir relleno si es necesario
    while(translated.size() % 4 != 0) {
        translated.push_back('=');
    }
    
    // Decode
    decoder.Put(translated.data(), translated.size());
    decoder.MessageEnd();
    
    size_t size = decoder.MaxRetrievable();
    if(size) {
        decoded.resize(size);
        decoder.Get(reinterpret_cast<uint8_t*>(&decoded[0]), size);
    }
    
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::vector<uint8_t> reverse_by_word(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    for(size_t i = 0; i < data.size(); i += 4) {
        auto remaining = std::min(size_t(4), data.size() - i);
        result.insert(result.end(), data.begin() + i, data.begin() + i + remaining);
        std::reverse(result.end() - remaining, result.end());
    }
    
    return result;
}

std::vector<uint8_t> int_to_bytes(const CryptoPP::Integer& n) {
    size_t byte_length = (n.BitCount() + 7) / 8;
    std::vector<uint8_t> result(byte_length);
    n.Encode(result.data(), byte_length, CryptoPP::Integer::UNSIGNED);
    std::reverse(result.begin(), result.end());  // Convertir a little-endian
    return result;
}

CryptoPP::Integer bytes_to_int(const std::vector<uint8_t>& bytes) {
    CryptoPP::Integer r("0");
    for (size_t i = 0; i < bytes.size(); ++i) {
        r += CryptoPP::Integer(bytes[i]) << (i * 8); // Convertir a little-endian
    }
    return r;
}

std::vector<uint8_t> LicenseEncoder::gen_padding_lic(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result;
    if(data.empty()) {
        result.push_back(0);
    } else {
        result.push_back(static_cast<uint8_t>(data.size()));
        result.insert(result.end(), data.begin(), data.end());
    }
    return result;
}

CryptoPP::Integer rsa_encrypt_decrypt(const CryptoPP::Integer& data,
                                    const CryptoPP::Integer& exp,
                                    const CryptoPP::Integer& mod) {
    return a_exp_b_mod_c(data, exp, mod);
}

std::tuple<CryptoPP::Integer, CryptoPP::Integer, CryptoPP::Integer> get_rsa_key_info() {
    std::string key(PUBLIC_KEY);
    auto pos = key.find(':');
    std::vector<uint8_t> bs_e(key.begin(), key.begin() + pos);
    std::vector<uint8_t> bs_n(key.begin() + pos + 1, key.end());

    auto dec_e = base64_decode_ext(bs_e);
    auto dec_n = base64_decode_ext(bs_n);
    auto rev_e = reverse_by_word(dec_e);
    auto rev_n = reverse_by_word(dec_n);

    CryptoPP::Integer e, n, d;

    e = bytes_to_int(rev_e);
    n = bytes_to_int(rev_n);

    std::string hex_d(PRIVATE_KEY + "h"); // Para analizarlo en modo hexadecimal
    d = CryptoPP::Integer(hex_d.c_str());

    return std::make_tuple(e, d, n);
}

LicenseEncoder::LicenseEncoder(const std::string& username, const std::string& atsite,
                             int user_num, const std::string& serial_num, uint8_t lic_type)
    : username(username), atsite(atsite), user_num(user_num),
      serial_num(serial_num), license_type(lic_type) {}

std::vector<uint8_t> LicenseEncoder::gen_lic() {
    std::vector<uint8_t> lic = {0x04, 'S', 'C', 'T', 'R'};
    std::vector<uint8_t> empty;
    auto padded_empty = gen_padding_lic(empty);
    
    // Añadir 5 rellenos vacíos
    for(int i = 0; i < 5; ++i) {
        lic.insert(lic.end(), padded_empty.begin(), padded_empty.end());
    }
    
    // Añadir información sobre la organización y la versión
    lic.push_back(0x01);
    std::vector<uint8_t> org_id = {'7', '3', '0', '5', '1'};
    auto padded_org = gen_padding_lic(org_id);
    lic.insert(lic.end(), padded_org.begin(), padded_org.end());
    
    std::string org_info = std::to_string(user_num) + "|" + atsite;
    std::vector<uint8_t> org_data(org_info.begin(), org_info.end());
    auto padded_org_data = gen_padding_lic(org_data);
    lic.insert(lic.end(), padded_org_data.begin(), padded_org_data.end());
    
    lic.push_back(0x06);
    lic.push_back(license_type);
    
    // Añadir datos aleatorios
    CryptoPP::AutoSeededRandomPool rng;
    uint8_t random_bytes[5];
    rng.GenerateBlock(random_bytes, sizeof(random_bytes));
    lic.insert(lic.end(), random_bytes, random_bytes + sizeof(random_bytes));
    
    lic.push_back(0x09);
    std::vector<uint8_t> serial_data(serial_num.begin(), serial_num.end());
    lic.insert(lic.end(), serial_data.begin(), serial_data.end());
    
    std::vector<uint8_t> zero = {'0'};
    std::vector<uint8_t> thirty = {'3', '0'};
    std::vector<uint8_t> fifteen = {'1', '5'};
    
    auto padded_zero = gen_padding_lic(zero);
    auto padded_thirty = gen_padding_lic(thirty);
    auto padded_fifteen = gen_padding_lic(fifteen);
    
    lic.insert(lic.end(), padded_zero.begin(), padded_zero.end());
    lic.insert(lic.end(), padded_thirty.begin(), padded_thirty.end());
    lic.insert(lic.end(), padded_fifteen.begin(), padded_fifteen.end());
    
    // Añadir nombre de usuario
    std::vector<uint8_t> user_data(username.begin(), username.end());
    auto padded_user = gen_padding_lic(user_data);
    lic.insert(lic.end(), padded_user.begin(), padded_user.end());
    
    // Añadir final
    auto padded_end = gen_padding_lic(zero);
    lic.insert(lic.end(), padded_end.begin(), padded_end.end());
    lic.insert(lic.end(), padded_end.begin(), padded_end.end());
    
    // Añadir relleno para que el tamaño sea múltiplo de 255
    size_t padding_size = 255 - (lic.size() % 255);
    lic.insert(lic.end(), padding_size, padding_size);
    
    return lic;
}

std::string LicenseEncoder::encode() {
    auto lic = gen_lic();
    CryptoPP::Integer lic_data = bytes_to_int(lic);
    
    auto [e, d, n] = get_rsa_key_info();
    auto enc_data = rsa_encrypt_decrypt(lic_data, d, n);
    auto data = int_to_bytes(enc_data);
    
    // Base58 encode
    size_t b58_size = data.size() * 2;  // Garantizar espacio suficiente
    std::vector<char> b58_str(b58_size);
    
    if (!b58enc(b58_str.data(), &b58_size, data.data(), data.size())) {
        throw std::runtime_error("Base58 encoding failed");
    }
    
    std::string result = "--- BEGIN LICENSE KEY ---\r\n";
    result.append(b58_str.data(), b58_size);
    result += "\r\n--- END LICENSE KEY -----\r\n";
    
    return result;
}

LicenseDecoder::LicenseDecoder(const std::string& lic_key) {
    std::string stripped_key = lic_key;
    stripped_key.erase(0, strlen("--- BEGIN LICENSE KEY ---\r\n"));
    stripped_key.erase(stripped_key.end() - 1 - strlen("\r\n--- END LICENSE KEY -----\r\n"),
                      stripped_key.end());
    
    // Base58 decode
    std::vector<uint8_t> decoded_data(stripped_key.size() * 2);  // Garantizar espacio suficiente
    size_t decoded_size = decoded_data.size();
    
    if (!b58tobin(decoded_data.data(), &decoded_size, 
                 stripped_key.c_str(), stripped_key.length())) {
        throw std::runtime_error("Base58 decoding failed");
    }
    decoded_data.erase(decoded_data.begin(), decoded_data.end() - decoded_size); // Reservar el último $$decoded_size$$-th data
    
    CryptoPP::Integer enc_data = bytes_to_int(decoded_data);
    
    auto [e, d, n] = get_rsa_key_info();
    auto dec_result = rsa_encrypt_decrypt(enc_data, e, n);
    
    data = int_to_bytes(dec_result);
}

std::tuple<int, std::string> LicenseDecoder::dec_org() {
    std::vector<uint8_t> pattern = {0x05, '7', '3', '0', '5', '1'};
    auto preIt = std::search(data.begin(), data.end(), pattern.begin(), pattern.end());
    if (preIt == data.end()) {
        throw std::runtime_error("Invalid license format: organization info not found");
    }
    
    size_t pre_idx = std::distance(data.begin(), preIt) + 7;
    std::vector<uint8_t> tmp_data(data.begin() + pre_idx, data.end());
    
    std::vector<uint8_t> ver_pattern = {0x06};
    auto postIt = std::search(tmp_data.begin(), tmp_data.end(), 
                             ver_pattern.begin(), ver_pattern.end());
    if (postIt == tmp_data.end()) {
        throw std::runtime_error("Invalid license format: version info not found");
    }
    
    size_t post_idx = std::distance(tmp_data.begin(), postIt);
    std::string info(tmp_data.begin(), tmp_data.begin() + post_idx);
    
    auto sep_pos = info.find('|');
    if (sep_pos == std::string::npos) {
        throw std::runtime_error("Invalid license format: separator not found");
    }
    
    std::string num_str = info.substr(0, sep_pos);
    std::string atsite = info.substr(sep_pos + 1);
    
    // Eliminar los espacios en blanco finales
    atsite.erase(std::find_if(atsite.rbegin(), atsite.rend(), 
                             [](unsigned char ch) { return !std::isspace(ch); }).base(),
                 atsite.end());
    
    data = std::vector<uint8_t>(tmp_data.begin(), tmp_data.end());
    return std::make_tuple(std::stoi(num_str), atsite);
}

std::string LicenseDecoder::dec_version() {
    std::vector<uint8_t> ver_pattern = {0x06};
    auto preIt = std::search(data.begin(), data.end(), 
                            ver_pattern.begin(), ver_pattern.end());
    if (preIt == data.end()) {
        throw std::runtime_error("Invalid license format: version pattern not found");
    }
    
    size_t pre_idx = std::distance(data.begin(), preIt) + 1;
    std::vector<uint8_t> version_data(data.begin() + pre_idx, data.begin() + pre_idx + 1);
    
    data = std::vector<uint8_t>(data.begin() + pre_idx, data.end());
    
    std::stringstream ss;
    ss << "0x" << std::hex << static_cast<int>(version_data[0]);
    return ss.str();
}

std::tuple<std::string, std::string> LicenseDecoder::dec_random() {
    std::vector<uint8_t> rand_pattern = {0x09};
    auto preIt = std::search(data.begin(), data.end(), 
                            rand_pattern.begin(), rand_pattern.end());
    if (preIt == data.end()) {
        throw std::runtime_error("Invalid license format: random pattern not found");
    }
    
    size_t pre_idx = std::distance(data.begin(), preIt);
    CryptoPP::Integer rand_1;
    rand_1.Decode(data.data() + 1, pre_idx - 1, CryptoPP::Integer::UNSIGNED);
    
    std::vector<uint8_t> tmp_data(data.begin() + pre_idx, data.end());
    
    std::vector<uint8_t> next_pattern = {0x01, '0', 0x02, '3', '0', 0x02, '1', '5'};
    auto postIt = std::search(tmp_data.begin(), tmp_data.end(),
                             next_pattern.begin(), next_pattern.end());
    if (postIt == tmp_data.end()) {
        throw std::runtime_error("Invalid license format: separator pattern not found");
    }
    
    size_t post_idx = std::distance(tmp_data.begin(), postIt);
    std::string serial_str(tmp_data.begin() + 1, tmp_data.begin() + post_idx);
    
    std::stringstream rand_ss;
    rand_ss << "0x" << std::hex << rand_1;
    
    data = std::vector<uint8_t>(tmp_data.begin(), tmp_data.end());
    
    // Dividir el número de serie por '-'
    auto sep_pos = serial_str.find('-');
    if (sep_pos == std::string::npos) {
        throw std::runtime_error("Invalid license format: serial number separator not found");
    }
    
    std::string part1 = serial_str.substr(0, sep_pos);
    std::string part2 = serial_str.substr(sep_pos + 1);
    
    return std::make_tuple(rand_ss.str(), part1 + "-" + part2);
}

std::string LicenseDecoder::dec_uname() {
    std::vector<uint8_t> pattern = {0x01, 0x30, 0x02, '3', '0', 0x02, '1', '5'};
    auto preIt = std::search(data.begin(), data.end(), 
                            pattern.begin(), pattern.end());
    if (preIt == data.end()) {
        throw std::runtime_error("Invalid license format: username pattern not found");
    }
    
    size_t pre_idx = std::distance(data.begin(), preIt) + 9;
    std::vector<uint8_t> tmp_data(data.begin() + pre_idx, data.end());
    
    std::vector<uint8_t> end_pattern = {0x01, '0', 0x01, '0'};
    auto postIt = std::search(tmp_data.begin(), tmp_data.end(),
                             end_pattern.begin(), end_pattern.end());
    if (postIt == tmp_data.end()) {
        throw std::runtime_error("Invalid license format: end pattern not found");
    }
    
    size_t post_idx = std::distance(tmp_data.begin(), postIt);
    std::string username(tmp_data.begin(), tmp_data.begin() + post_idx);
    
    data = std::vector<uint8_t>(tmp_data.begin(), tmp_data.end());
    return username;
}

std::tuple<int, std::string, std::string, std::string, std::string, std::string>
LicenseDecoder::decode() {
    auto [num, atsite] = dec_org();
    std::string version = dec_version();
    auto [rand, serial_num] = dec_random();
    std::string username = dec_uname();
    
    return std::make_tuple(num, atsite, version, rand, serial_num, username);
}
