#pragma once

#include <atomic>

#include "envoy/common/time.h"
#include "envoy/compression/compressor/compressor.h"

#define HAVE_QAT_HEADERS
#include "qatzip.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Qatzip {
namespace Compressor {

class QatzipFallbackState {
public:
  QatzipFallbackState(uint32_t max_concurrent_operations,
                      std::chrono::milliseconds latency_threshold,
                      std::chrono::milliseconds cooldown);

  bool tryAcquire(MonotonicTime now);
  void acquire();
  void release(MonotonicTime start, MonotonicTime end);

private:
  static int64_t toNanoseconds(MonotonicTime time);

  const uint32_t max_concurrent_operations_;
  const std::chrono::milliseconds latency_threshold_;
  const std::chrono::milliseconds cooldown_;
  std::atomic<uint32_t> active_operations_{0};
  std::atomic<int64_t> cooldown_deadline_ns_{0};
};

using QatzipFallbackStateSharedPtr = std::shared_ptr<QatzipFallbackState>;

/**
 * Implementation of compressor's interface.
 */
class QatzipCompressorImpl : public Envoy::Compression::Compressor::Compressor {
public:
  QatzipCompressorImpl(QzSession_T* session);

  /**
   * Constructor that allows setting the size of compressor's output buffer. It
   * should be called whenever a buffer size different than the 4096 bytes, normally set by the
   * default constructor, is desired.
   * @param chunk_size amount of memory reserved for the compressor output.
   */
  QatzipCompressorImpl(QzSession_T* session, size_t chunk_size);
  QatzipCompressorImpl(
      QzSession_T* session, size_t chunk_size,
      Envoy::Compression::Compressor::CompressorPtr&& software_compressor,
      QatzipFallbackStateSharedPtr fallback_state, TimeSource& time_source);
  ~QatzipCompressorImpl() override;

  // Compressor
  void compress(Buffer::Instance& buffer, Envoy::Compression::Compressor::State state) override;

private:
  enum class Selection { Undecided, Qatzip, Software };

  void process(Buffer::Instance& output_buffer, unsigned int last);

  const size_t chunk_size_;
  size_t avail_in_;
  size_t avail_out_;

  std::unique_ptr<unsigned char[]> chunk_char_ptr_;
  QzSession_T* const session_;
  QzStream_T stream_;

  uint32_t input_len_;
  Envoy::Compression::Compressor::CompressorPtr software_compressor_;
  QatzipFallbackStateSharedPtr fallback_state_;
  TimeSource* const time_source_{nullptr};
  Selection selection_{Selection::Qatzip};
  bool operation_reserved_{false};
};

} // namespace Compressor
} // namespace Qatzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
