#ifdef LOCKEY_HAS_VERIFY

#include <grpcpp/support/slice.h>
#include <lockey/verify/codec.hpp>

namespace lockey::verify {

    // Helper: Convert std::vector<uint8_t> to gRPC ByteBuffer
    grpc::ByteBuffer CustomCodec::to_byte_buffer(const std::vector<uint8_t> &data) {
        grpc::Slice slice(data.data(), data.size());
        return grpc::ByteBuffer(&slice, 1);
    }

    // Helper: Convert gRPC ByteBuffer to std::vector<uint8_t>
    std::vector<uint8_t> CustomCodec::from_byte_buffer(grpc::ByteBuffer *buffer) {
        std::vector<grpc::Slice> slices;
        if (!buffer->Dump(&slices).ok()) {
            return {};
        }

        // Calculate total size
        size_t total_size = 0;
        for (const auto &slice : slices) {
            total_size += slice.size();
        }

        // Copy all slices into a single vector
        std::vector<uint8_t> result;
        result.reserve(total_size);
        for (const auto &slice : slices) {
            const uint8_t *data = reinterpret_cast<const uint8_t *>(slice.begin());
            result.insert(result.end(), data, data + slice.size());
        }

        return result;
    }

    // Client-side: Serialize request
    grpc::Status CustomCodec::serialize_request(const wire::VerifyRequest &request, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(request);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::serialize_request(const wire::BatchVerifyRequest &request, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(request);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::serialize_request(const wire::HealthCheckRequest &request, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(request);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

    // Client-side: Deserialize response
    grpc::Status CustomCodec::deserialize_response(grpc::ByteBuffer *input, wire::VerifyResponse &response) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty response buffer");
            }

            if (!wire::Serializer::deserialize(data, response)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::deserialize_response(grpc::ByteBuffer *input, wire::BatchVerifyResponse &response) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty response buffer");
            }

            if (!wire::Serializer::deserialize(data, response)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::deserialize_response(grpc::ByteBuffer *input, wire::HealthCheckResponse &response) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty response buffer");
            }

            if (!wire::Serializer::deserialize(data, response)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    // Server-side: Deserialize request
    grpc::Status CustomCodec::deserialize_request(grpc::ByteBuffer *input, wire::VerifyRequest &request) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty request buffer");
            }

            if (!wire::Serializer::deserialize(data, request)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::deserialize_request(grpc::ByteBuffer *input, wire::BatchVerifyRequest &request) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty request buffer");
            }

            if (!wire::Serializer::deserialize(data, request)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::deserialize_request(grpc::ByteBuffer *input, wire::HealthCheckRequest &request) {
        try {
            auto data = from_byte_buffer(input);
            if (data.empty()) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Empty request buffer");
            }

            if (!wire::Serializer::deserialize(data, request)) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Deserialization failed");
            }

            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Deserialization failed: ") + e.what());
        }
    }

    // Server-side: Serialize response
    grpc::Status CustomCodec::serialize_response(const wire::VerifyResponse &response, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(response);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::serialize_response(const wire::BatchVerifyResponse &response, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(response);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

    grpc::Status CustomCodec::serialize_response(const wire::HealthCheckResponse &response, grpc::ByteBuffer *output) {
        try {
            auto data = wire::Serializer::serialize(response);
            *output = to_byte_buffer(data);
            return grpc::Status::OK;
        } catch (const std::exception &e) {
            return grpc::Status(grpc::StatusCode::INTERNAL, std::string("Serialization failed: ") + e.what());
        }
    }

} // namespace lockey::verify

#endif // LOCKEY_HAS_VERIFY
