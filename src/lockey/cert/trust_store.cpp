#include <lockey/cert/trust_store.hpp>

#include <algorithm>
#include <cstdlib>
#include <string_view>

#include <lockey/cert/pem.hpp>
#include <lockey/io/files.hpp>

namespace lockey::cert {

bool TrustStore::add(const Certificate &cert) {
    anchors_.push_back(cert);
    return true;
}

bool TrustStore::remove_by_subject(const DistinguishedName &subject) {
    auto original = anchors_.size();
    anchors_.erase(std::remove_if(anchors_.begin(), anchors_.end(),
                                  [&](const Certificate &cert) { return cert.tbs().subject.der() == subject.der(); }),
                   anchors_.end());
    return anchors_.size() != original;
}

std::optional<Certificate> TrustStore::find_issuer(const Certificate &cert) const {
    for (const auto &anchor : anchors_) {
        if (anchor.tbs().subject.der() == cert.tbs().issuer.der()) {
            return anchor;
        }
    }
    return std::nullopt;
}

CertificateResult<TrustStore> TrustStore::load_from_pem(const std::string &path) {
    auto chain = Certificate::load(path, true);
    if (!chain.success) {
        return CertificateResult<TrustStore>::failure(chain.error);
    }
    TrustStore store;
    for (const auto &cert : chain.value) {
        store.add(cert);
    }
    return CertificateResult<TrustStore>::ok(std::move(store));
}

CertificateResult<TrustStore> TrustStore::load_from_der(const std::string &path) {
    auto chain = Certificate::load(path, true);
    if (!chain.success) {
        return CertificateResult<TrustStore>::failure(chain.error);
    }
    TrustStore store;
    for (const auto &cert : chain.value) {
        store.add(cert);
    }
    return CertificateResult<TrustStore>::ok(std::move(store));
}

CertificateResult<TrustStore> TrustStore::load_from_file(const std::string &path) {
    auto file = io::read_binary(path);
    if (!file.success) {
        return CertificateResult<TrustStore>::failure(file.error_message);
    }
    const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());
    if (contents.find("-----BEGIN") != std::string_view::npos) {
        return load_from_pem(path);
    }
    return load_from_der(path);
}

CertificateResult<TrustStore> TrustStore::load_from_system() {
    const char *env_file = std::getenv("SSL_CERT_FILE");
    if (env_file && env_file[0] != '\0') {
        auto store = load_from_file(env_file);
        if (store.success) {
            return store;
        }
    }
    constexpr const char *default_paths[] = {
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",   // CentOS/RHEL
        "/usr/local/share/certs/ca-root-nss.crt" // FreeBSD
    };
    for (const auto *path : default_paths) {
        auto store = load_from_file(path);
        if (store.success) {
            return store;
        }
    }
    return CertificateResult<TrustStore>::failure("unable to locate system trust store");
}

} // namespace lockey::cert
