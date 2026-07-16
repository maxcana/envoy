#include "contrib/qat/compression/qatzip/compressor/source/config.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/compression/gzip/compressor/config.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Qatzip {
namespace Compressor {

#ifndef QAT_DISABLED
namespace {

// Default qatzip chunk size.
const uint32_t DefaultChunkSize = 4096;

// Default qatzip stream buffer size.
const unsigned int DefaultStreamBufferSize = 128 * 1024;

const uint32_t DefaultTargetConcurrentQzcompressOps = 64;

unsigned int hardwareBufferSizeEnum(
    envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize
        hardware_buffer_size) {
  switch (hardware_buffer_size) {
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_4K:
    return 4 * 1024;
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_8K:
    return 8 * 1024;
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_32K:
    return 32 * 1024;
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_64K:
    return 64 * 1024;
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_128K:
    return 128 * 1024;
  case envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip_HardwareBufferSize::
      Qatzip_HardwareBufferSize_SZ_512K:
    return 512 * 1024;
  default:
    return 64 * 1024;
  }
}

unsigned int compressionLevelUint(Protobuf::uint32 compression_level) {
  return compression_level > 0 ? compression_level : QZ_COMP_LEVEL_DEFAULT;
}

unsigned int inputSizeThresholdUint(Protobuf::uint32 input_size_threshold) {
  return input_size_threshold > 0 ? input_size_threshold : QZ_COMP_THRESHOLD_DEFAULT;
}

unsigned int streamBufferSizeUint(Protobuf::uint32 stream_buffer_size) {
  return stream_buffer_size > 0 ? stream_buffer_size : DefaultStreamBufferSize;
}

} // namespace

QatzipCompressorFactory::QatzipCompressorFactory(
    const envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip& qatzip,
    Server::Configuration::GenericFactoryContext& context)
    : compression_level_(compressionLevelUint(qatzip.compression_level().value())),
      chunk_size_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(qatzip, chunk_size, DefaultChunkSize)),
      tls_slot_(context.serverFactoryContext().threadLocal().allocateSlot()) {
  QzSessionParams_T params;

  int status = qzGetDefaults(&params);
  RELEASE_ASSERT(status == QZ_OK, "failed to initialize hardware");
  params.comp_lvl = compression_level_;
  params.hw_buff_sz = hardwareBufferSizeEnum(qatzip.hardware_buffer_size());
  params.strm_buff_sz = streamBufferSizeUint(qatzip.stream_buffer_size().value());
  params.input_sz_thrshold = inputSizeThresholdUint(qatzip.input_size_threshold().value());
  params.data_fmt = QZ_DEFLATE_RAW;

  tls_slot_->set([params](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return std::make_shared<QatzipThreadLocal>(params);
  });

  if (qatzip.has_gzip_fallback()) {
    const auto& fallback = qatzip.gzip_fallback();
    envoy::extensions::compression::gzip::compressor::v3::Gzip gzip;
    if (fallback.has_gzip()) {
      MessageUtil::anyConvertAndValidate(fallback.gzip(), gzip,
                                         context.messageValidationVisitor());
    } else {
      gzip.set_compression_level(
          static_cast<envoy::extensions::compression::gzip::compressor::v3::Gzip::CompressionLevel>(
              compression_level_));
      gzip.mutable_window_bits()->set_value(15);
      gzip.mutable_chunk_size()->set_value(chunk_size_);
    }
    gzip_compressor_factory_ =
        std::make_unique<Compression::Gzip::Compressor::GzipCompressorFactory>(gzip);
    operation_state_ = std::make_shared<QatzipOperationState>(PROTOBUF_GET_WRAPPED_OR_DEFAULT(
        fallback, target_concurrent_qzcompress_ops, DefaultTargetConcurrentQzcompressOps));
  }
}

Envoy::Compression::Compressor::CompressorPtr QatzipCompressorFactory::createCompressor() {
  if (operation_state_ != nullptr) {
    return std::make_unique<QatzipCompressorImpl>(
        tls_slot_->getTyped<QatzipThreadLocal>().getSession(), chunk_size_,
        gzip_compressor_factory_->createCompressor(), operation_state_);
  }
  return std::make_unique<QatzipCompressorImpl>(
      tls_slot_->getTyped<QatzipThreadLocal>().getSession(), chunk_size_);
}

QatzipCompressorFactory::QatzipThreadLocal::QatzipThreadLocal(QzSessionParams_T params)
    : params_(params), session_{} {}

QatzipCompressorFactory::QatzipThreadLocal::~QatzipThreadLocal() {
  if (initialized_) {
    qzTeardownSession(&session_);
    qzClose(&session_);
  }
}

QzSession_T* QatzipCompressorFactory::QatzipThreadLocal::getSession() {
  // The session must be initialized only once in every worker thread.
  if (!initialized_) {

    int status = qzInit(&session_, params_.sw_backup);
    RELEASE_ASSERT(status == QZ_OK || status == QZ_DUPLICATE, "failed to initialize hardware");
    status = qzSetupSession(&session_, &params_);
    RELEASE_ASSERT(status == QZ_OK || status == QZ_DUPLICATE, "failed to setup session");
    initialized_ = true;
  }

  return &session_;
}

Envoy::Compression::Compressor::CompressorFactoryPtr
QatzipCompressorLibraryFactory::createCompressorFactoryFromProtoTyped(
    const envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip& proto_config,
    Server::Configuration::GenericFactoryContext& context) {
  return std::make_unique<QatzipCompressorFactory>(proto_config, context);
}
#endif

Envoy::Compression::Compressor::CompressorFactoryPtr
QatzipCompressorLibraryFactory::createCompressorFactoryFromProto(
    const Protobuf::Message& proto_config, Server::Configuration::GenericFactoryContext& context) {

  const envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip config =
      MessageUtil::downcastAndValidate<
          const envoy::extensions::compression::qatzip::compressor::v3alpha::Qatzip&>(
          proto_config, context.messageValidationVisitor());
#ifdef QAT_DISABLED
  static_cast<void>(config);
  throw EnvoyException("X86_64 architecture is required for QAT.");
#else
  return createCompressorFactoryFromProtoTyped(config, context);
#endif
}

/**
 * Static registration for the qatzip compressor library. @see NamedCompressorLibraryConfigFactory.
 */
REGISTER_FACTORY(QatzipCompressorLibraryFactory,
                 Envoy::Compression::Compressor::NamedCompressorLibraryConfigFactory);

} // namespace Compressor
} // namespace Qatzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
