#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <lockey/cert/asn1_common.hpp>
#include <lockey/cert/asn1_utils.hpp>
#include <lockey/cert/certificate.hpp>
#include <lockey/cert/oid_registry.hpp>

namespace lockey::cert {

struct CertificateContext {
    std::vector<uint8_t> der;
    std::vector<uint8_t> tbs_certificate;
    int version{1};
    std::vector<uint8_t> serial_number;
    AlgorithmIdentifier tbs_signature{};
    DistinguishedName issuer{};
    DistinguishedName subject{};
    std::chrono::system_clock::time_point not_before{};
    std::chrono::system_clock::time_point not_after{};
    SubjectPublicKeyInfo subject_public_key_info{};
    std::vector<RawExtension> extensions;
    AlgorithmIdentifier outer_signature{};
    std::vector<uint8_t> signature_value;
};

struct ParseResult {
    bool success{};
    CertificateContext certificate{};
    std::string error{};
};

ParseResult parse_x509_cert(ByteSpan input);
ParseResult parse_x509_cert_relaxed(ByteSpan input);

} // namespace lockey::cert
