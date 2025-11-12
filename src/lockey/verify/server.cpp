#ifdef LOCKEY_HAS_VERIFY

#include <lockey/verify/server.hpp>
#include <lockey/verify/codec.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server_builder.h>
#include <grpc/support/log.h>

#include <atomic>
#include <cassert>
#include <iostream>
#include <sodium.h>
#include <thread>

namespace lockey::verify {

// SimpleRevocationHandler implementation
void SimpleRevocationHandler::add_revoked_certificate(
    const std::vector<uint8_t>& serial_number,
    const std::string& reason,
    std::chrono::system_clock::time_point revocation_time) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    RevocationInfo info;
    info.reason = reason;
    info.revocation_time = revocation_time;
    info.this_update = std::chrono::system_clock::now();
    info.next_update = info.this_update + std::chrono::hours(24);
    revoked_certs_[serial_number] = info;
}

void SimpleRevocationHandler::remove_revoked_certificate(const std::vector<uint8_t>& serial_number) {
    std::lock_guard<std::mutex> lock(mutex_);
    revoked_certs_.erase(serial_number);
}

bool SimpleRevocationHandler::is_revoked(const std::vector<uint8_t>& serial_number) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return revoked_certs_.find(serial_number) != revoked_certs_.end();
}

void SimpleRevocationHandler::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    revoked_certs_.clear();
}

wire::VerifyResponse SimpleRevocationHandler::verify_chain(
    const std::vector<cert::Certificate>& chain,
    std::chrono::system_clock::time_point validation_time) {
    
    wire::VerifyResponse response;
    if (chain.empty()) {
        response.status = wire::VerifyStatus::UNKNOWN;
        response.reason = "Empty certificate chain";
        return response;
    }

    const auto& cert = chain[0];
    const auto& serial = cert.tbs().serial_number;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = revoked_certs_.find(serial);

    if (it != revoked_certs_.end()) {
        response.status = wire::VerifyStatus::REVOKED;
        response.reason = it->second.reason;
        response.revocation_time = it->second.revocation_time;
        response.this_update = it->second.this_update;
        response.next_update = it->second.next_update;
    } else {
        response.status = wire::VerifyStatus::GOOD;
        response.reason = "Certificate is valid";
        response.this_update = std::chrono::system_clock::now();
        response.next_update = response.this_update + std::chrono::hours(24);
    }
    return response;
}

// Server implementation  
class Server::Impl {
public:
    std::shared_ptr<VerificationHandler> handler;
    ServerConfig config;
    std::unique_ptr<grpc::Server> grpc_server;
    std::unique_ptr<grpc::AsyncGenericService> generic_service;
    std::unique_ptr<grpc::ServerCompletionQueue> cq;
    std::atomic<bool> running{false};

    std::vector<uint8_t> signing_key;
    std::optional<cert::Certificate> responder_cert;

    Server::Stats stats;
    mutable std::mutex stats_mutex;

    explicit Impl(std::shared_ptr<VerificationHandler> h, const ServerConfig& cfg)
        : handler(std::move(h)), config(cfg) {
        stats.start_time = std::chrono::system_clock::now();
    }

    void handle_verify_request(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer);
    void handle_batch_request(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer);
    void handle_health_check(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer);
    void sign_response(wire::VerifyResponse& response);
    void handle_rpcs();
};

namespace {
    // Call state for handling individual RPCs
    class CallData {
    public:
        CallData(Server::Impl* impl, grpc::AsyncGenericService* service, grpc::ServerCompletionQueue* cq)
            : impl_(impl), service_(service), cq_(cq), stream_(&ctx_), status_(CREATE) {
            Proceed();
        }

        void Proceed() {
            if (status_ == CREATE) {
                status_ = PROCESS;
                service_->RequestCall(&ctx_, &stream_, cq_, cq_, this);
            } else if (status_ == PROCESS) {
                new CallData(impl_, service_, cq_);
                stream_.Read(&request_buffer_, this);
                status_ = READING;
            } else if (status_ == READING) {
                std::string method = ctx_.method();
                if (method == "/lockey.verify.VerifyService/CheckCertificate") {
                    impl_->handle_verify_request(request_buffer_, response_buffer_);
                } else if (method == "/lockey.verify.VerifyService/CheckBatch") {
                    impl_->handle_batch_request(request_buffer_, response_buffer_);
                } else if (method == "/lockey.verify.VerifyService/HealthCheck") {
                    impl_->handle_health_check(request_buffer_, response_buffer_);
                } else {
                    stream_.Finish(grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "Unknown method"), this);
                    status_ = FINISH;
                    return;
                }
                stream_.WriteAndFinish(response_buffer_, grpc::WriteOptions(), grpc::Status::OK, this);
                status_ = FINISH;
            } else {
                assert(status_ == FINISH);
                delete this;
            }
        }

    private:
        enum CallStatus { CREATE, PROCESS, READING, FINISH };
        
        Server::Impl* impl_;
        grpc::AsyncGenericService* service_;
        grpc::ServerCompletionQueue* cq_;
        grpc::GenericServerContext ctx_;
        grpc::GenericServerAsyncReaderWriter stream_;
        grpc::ByteBuffer request_buffer_;
        grpc::ByteBuffer response_buffer_;
        CallStatus status_;
    };
}

void Server::Impl::sign_response(wire::VerifyResponse& response) {
    if (signing_key.size() != crypto_sign_SECRETKEYBYTES) {
        return;
    }

    std::vector<uint8_t> message;
    message.push_back(static_cast<uint8_t>(response.status));
    message.insert(message.end(), response.reason.begin(), response.reason.end());

    auto rev_time = std::chrono::system_clock::to_time_t(response.revocation_time);
    auto this_time = std::chrono::system_clock::to_time_t(response.this_update);
    auto next_time = std::chrono::system_clock::to_time_t(response.next_update);

    for (int i = 0; i < 8; i++) {
        message.push_back(static_cast<uint8_t>((rev_time >> (i * 8)) & 0xFF));
    }
    for (int i = 0; i < 8; i++) {
        message.push_back(static_cast<uint8_t>((this_time >> (i * 8)) & 0xFF));
    }
    for (int i = 0; i < 8; i++) {
        message.push_back(static_cast<uint8_t>((next_time >> (i * 8)) & 0xFF));
    }

    message.insert(message.end(), response.nonce.begin(), response.nonce.end());

    response.signature.resize(crypto_sign_BYTES);
    crypto_sign_detached(response.signature.data(), nullptr,
                       message.data(), message.size(),
                           signing_key.data());
}

void Server::Impl::handle_verify_request(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer) {
    wire::VerifyRequest wire_req;
    auto deserialize_status = CustomCodec::deserialize_request(&request_buffer, wire_req);

    if (!deserialize_status.ok()) {
        wire::VerifyResponse error_resp;
        error_resp.status = wire::VerifyStatus::UNKNOWN;
        error_resp.reason = "Failed to deserialize request";
        CustomCodec::serialize_response(error_resp, &response_buffer);
        return;
    }

    std::vector<cert::Certificate> chain;
    for (const auto& cert_data : wire_req.certificate_chain) {
        auto parse_result = cert::Certificate::parse(cert_data.der_bytes);
        if (!parse_result.success) {
            wire::VerifyResponse error_resp;
            error_resp.status = wire::VerifyStatus::UNKNOWN;
            error_resp.reason = "Failed to parse certificate: " + parse_result.error;
            error_resp.nonce = wire_req.nonce;
            CustomCodec::serialize_response(error_resp, &response_buffer);
            return;
        }
        chain.push_back(std::move(parse_result.value));
    }

    auto response = handler->verify_chain(chain, wire_req.validation_timestamp);
    response.nonce = wire_req.nonce;

    if ((wire_req.flags & wire::RequestFlags::INCLUDE_RESPONDER_CERT) != wire::RequestFlags::NONE) {
        if (responder_cert.has_value()) {
            response.responder_cert_der = responder_cert->der();
        }
    }

    sign_response(response);

    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_requests++;
        switch (response.status) {
        case wire::VerifyStatus::GOOD: stats.good_responses++; break;
        case wire::VerifyStatus::REVOKED: stats.revoked_responses++; break;
        case wire::VerifyStatus::UNKNOWN: stats.unknown_responses++; break;
        }
    }

    CustomCodec::serialize_response(response, &response_buffer);
}

void Server::Impl::handle_batch_request(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer) {
    wire::BatchVerifyRequest batch_req;
    auto deserialize_status = CustomCodec::deserialize_request(&request_buffer, batch_req);

    if (!deserialize_status.ok()) {
        wire::BatchVerifyResponse error_resp;
        CustomCodec::serialize_response(error_resp, &response_buffer);
        return;
    }

    std::vector<std::vector<cert::Certificate>> chains;
    for (const auto& req : batch_req.requests) {
        std::vector<cert::Certificate> chain;
        for (const auto& cert_data : req.certificate_chain) {
            auto parse_result = cert::Certificate::parse(cert_data.der_bytes);
            if (parse_result.success) {
                chain.push_back(std::move(parse_result.value));
            }
        }
        chains.push_back(std::move(chain));
    }

    auto responses = handler->verify_batch(chains);

    for (size_t i = 0; i < responses.size() && i < batch_req.requests.size(); i++) {
        responses[i].nonce = batch_req.requests[i].nonce;
        sign_response(responses[i]);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_batch_requests++;
        for (const auto& resp : responses) {
            switch (resp.status) {
            case wire::VerifyStatus::GOOD: stats.good_responses++; break;
            case wire::VerifyStatus::REVOKED: stats.revoked_responses++; break;
            case wire::VerifyStatus::UNKNOWN: stats.unknown_responses++; break;
            }
        }
    }

    wire::BatchVerifyResponse batch_resp;
    batch_resp.responses = std::move(responses);
    CustomCodec::serialize_response(batch_resp, &response_buffer);
}

void Server::Impl::handle_health_check(grpc::ByteBuffer& request_buffer, grpc::ByteBuffer& response_buffer) {
    wire::HealthCheckRequest health_req;
    CustomCodec::deserialize_request(&request_buffer, health_req);

    wire::HealthCheckResponse health_resp;
    health_resp.status = handler->is_healthy() ? wire::HealthCheckResponse::ServingStatus::SERVING
                                               : wire::HealthCheckResponse::ServingStatus::NOT_SERVING;

    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.total_health_checks++;
    }

    CustomCodec::serialize_response(health_resp, &response_buffer);
}

void Server::Impl::handle_rpcs() {
    new CallData(this, generic_service.get(), cq.get());

    void* tag;
    bool ok;
    while (running) {
        if (cq->Next(&tag, &ok)) {
            if (ok) {
                static_cast<CallData*>(tag)->Proceed();
            } else {
                delete static_cast<CallData*>(tag);
            }
        }
    }
}

// Server public interface
Server::Server(std::shared_ptr<VerificationHandler> handler, const ServerConfig& config)
    : impl_(std::make_unique<Impl>(std::move(handler), config)) {}

Server::~Server() {
    if (impl_ && impl_->running) {
        stop();
    }
}

Server::Server(Server&&) noexcept = default;
Server& Server::operator=(Server&&) noexcept = default;

void Server::start() {
    if (impl_->running) {
        return;
    }

    grpc::ServerBuilder builder;

    std::shared_ptr<grpc::ServerCredentials> creds = grpc::InsecureServerCredentials();
    builder.AddListeningPort(impl_->config.address, creds);

    if (impl_->config.enable_compression) {
        builder.SetDefaultCompressionAlgorithm(GRPC_COMPRESS_GZIP);
    }

    impl_->generic_service = std::make_unique<grpc::AsyncGenericService>();
    builder.RegisterAsyncGenericService(impl_->generic_service.get());

    impl_->cq = builder.AddCompletionQueue();
    impl_->grpc_server = builder.BuildAndStart();

    if (!impl_->grpc_server) {
        throw std::runtime_error("Failed to start server on " + impl_->config.address);
    }

    impl_->running = true;
    std::cout << "Lockey Verification Server listening on " << impl_->config.address << std::endl;

    impl_->handle_rpcs();
}

void Server::start_async() {
    if (impl_->running) {
        return;
    }

    std::thread([this]() { this->start(); }).detach();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

void Server::stop() {
    if (!impl_->running) {
        return;
    }

    impl_->running = false;

    if (impl_->grpc_server) {
        impl_->grpc_server->Shutdown();
    }

    if (impl_->cq) {
        impl_->cq->Shutdown();
    }
}

void Server::wait() {
    while (impl_->running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool Server::is_running() const { return impl_->running; }

std::string Server::address() const { return impl_->config.address; }

void Server::set_signing_key(const std::vector<uint8_t>& ed25519_private_key) {
    if (ed25519_private_key.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument("Invalid Ed25519 private key size");
    }
    impl_->signing_key = ed25519_private_key;
}

void Server::set_responder_certificate(const cert::Certificate& cert) {
    impl_->responder_cert = cert;
}

Server::Stats Server::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    return impl_->stats;
}

} // namespace lockey::verify

#endif // LOCKEY_HAS_VERIFY
