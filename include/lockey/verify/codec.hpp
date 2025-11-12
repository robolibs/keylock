#pragma once

#ifdef LOCKEY_HAS_VERIFY

#include <grpcpp/grpcpp.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>
#include <lockey/verify/wire_format.hpp>

namespace lockey::verify {

    // Custom gRPC codec that bypasses Protobuf and uses our binary wire format
    // This codec is used by the gRPC client to serialize/deserialize messages
    class CustomCodec {
      public:
        // Serialize request to gRPC byte buffer
        static grpc::Status serialize_request(const wire::VerifyRequest &request, grpc::ByteBuffer *output);
        static grpc::Status serialize_request(const wire::BatchVerifyRequest &request, grpc::ByteBuffer *output);
        static grpc::Status serialize_request(const wire::HealthCheckRequest &request, grpc::ByteBuffer *output);

        // Deserialize response from gRPC byte buffer
        static grpc::Status deserialize_response(grpc::ByteBuffer *input, wire::VerifyResponse &response);
        static grpc::Status deserialize_response(grpc::ByteBuffer *input, wire::BatchVerifyResponse &response);
        static grpc::Status deserialize_response(grpc::ByteBuffer *input, wire::HealthCheckResponse &response);

        // Server-side: deserialize request
        static grpc::Status deserialize_request(grpc::ByteBuffer *input, wire::VerifyRequest &request);
        static grpc::Status deserialize_request(grpc::ByteBuffer *input, wire::BatchVerifyRequest &request);
        static grpc::Status deserialize_request(grpc::ByteBuffer *input, wire::HealthCheckRequest &request);

        // Server-side: serialize response
        static grpc::Status serialize_response(const wire::VerifyResponse &response, grpc::ByteBuffer *output);
        static grpc::Status serialize_response(const wire::BatchVerifyResponse &response, grpc::ByteBuffer *output);
        static grpc::Status serialize_response(const wire::HealthCheckResponse &response, grpc::ByteBuffer *output);

      private:
        // Helper to convert our serialized data to gRPC ByteBuffer
        static grpc::ByteBuffer to_byte_buffer(const std::vector<uint8_t> &data);

        // Helper to convert gRPC ByteBuffer to our vector
        static std::vector<uint8_t> from_byte_buffer(grpc::ByteBuffer *buffer);
    };

} // namespace lockey::verify

#endif // LOCKEY_HAS_VERIFY
