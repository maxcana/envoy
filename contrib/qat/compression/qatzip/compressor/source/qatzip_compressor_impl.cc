#include "contrib/qat/compression/qatzip/compressor/source/qatzip_compressor_impl.h"

#include <memory>

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace Compression {
namespace Qatzip {
namespace Compressor {

QatzipFallbackState::QatzipFallbackState(uint32_t max_concurrent_operations,
                                         std::chrono::milliseconds latency_threshold,
                                         std::chrono::milliseconds cooldown)
    : max_concurrent_operations_(max_concurrent_operations),
      latency_threshold_(latency_threshold), cooldown_(cooldown) {}

int64_t QatzipFallbackState::toNanoseconds(MonotonicTime time) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count();
}

bool QatzipFallbackState::tryAcquire(MonotonicTime now) {
  const int64_t now_ns = toNanoseconds(now);
  if (now_ns < cooldown_deadline_ns_.load(std::memory_order_relaxed)) {
    return false;
  }

  uint32_t active_operations = active_operations_.load(std::memory_order_relaxed);
  while (active_operations < max_concurrent_operations_) {
    if (active_operations_.compare_exchange_weak(active_operations, active_operations + 1,
                                                 std::memory_order_relaxed)) {
      if (now_ns < cooldown_deadline_ns_.load(std::memory_order_relaxed)) {
        active_operations_.fetch_sub(1, std::memory_order_relaxed);
        return false;
      }
      return true;
    }
  }
  return false;
}

void QatzipFallbackState::acquire() {
  active_operations_.fetch_add(1, std::memory_order_relaxed);
}

void QatzipFallbackState::release(MonotonicTime start, MonotonicTime end) {
  const uint32_t previous = active_operations_.fetch_sub(1, std::memory_order_relaxed);
  ASSERT(previous > 0);

  if (end - start < latency_threshold_) {
    return;
  }

  const int64_t new_deadline_ns = toNanoseconds(end + cooldown_);
  int64_t deadline_ns = cooldown_deadline_ns_.load(std::memory_order_relaxed);
  while (deadline_ns < new_deadline_ns &&
         !cooldown_deadline_ns_.compare_exchange_weak(deadline_ns, new_deadline_ns,
                                                      std::memory_order_relaxed)) {
  }
}

QatzipCompressorImpl::QatzipCompressorImpl(QzSession_T* session)
    : QatzipCompressorImpl(session, 4096) {}

// TODO(rojkov): add lower limit to chunk_size in proto definition.
QatzipCompressorImpl::QatzipCompressorImpl(QzSession_T* session, size_t chunk_size)
    : chunk_size_{chunk_size}, avail_in_{0}, avail_out_{chunk_size - 10},
      chunk_char_ptr_(new unsigned char[chunk_size]), session_{session}, stream_{}, input_len_(0) {
  RELEASE_ASSERT(session_ != nullptr,
                 "QATzip compressor must be created with non-null QATzip session");
  static unsigned char gzheader[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
  stream_.out = static_cast<unsigned char*>(mempcpy(chunk_char_ptr_.get(), gzheader, 10));
}

QatzipCompressorImpl::QatzipCompressorImpl(
    QzSession_T* session, size_t chunk_size,
    Envoy::Compression::Compressor::CompressorPtr&& software_compressor,
    QatzipFallbackStateSharedPtr fallback_state, TimeSource& time_source)
    : chunk_size_{chunk_size}, avail_in_{0}, avail_out_{chunk_size - 10},
      chunk_char_ptr_(new unsigned char[chunk_size]), session_{session}, stream_{}, input_len_(0),
      software_compressor_(std::move(software_compressor)),
      fallback_state_(std::move(fallback_state)), time_source_(&time_source),
      selection_(Selection::Undecided) {
  RELEASE_ASSERT(session_ != nullptr,
                 "QATzip compressor must be created with non-null QATzip session");
  static unsigned char gzheader[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
  stream_.out = static_cast<unsigned char*>(mempcpy(chunk_char_ptr_.get(), gzheader, 10));
}

QatzipCompressorImpl::~QatzipCompressorImpl() {
  if (selection_ != Selection::Software) {
    qzEndStream(session_, &stream_);
  }
}

void QatzipCompressorImpl::compress(Buffer::Instance& buffer,
                                    Envoy::Compression::Compressor::State state) {

  if (selection_ == Selection::Software) {
    software_compressor_->compress(buffer, state);
    return;
  }

  if (selection_ == Selection::Undecided) {
    if (buffer.length() == 0 && state != Envoy::Compression::Compressor::State::Finish) {
      return;
    }
    if (!fallback_state_->tryAcquire(time_source_->monotonicTime())) {
      selection_ = Selection::Software;
      software_compressor_->compress(buffer, state);
      return;
    }
    operation_reserved_ = true;
    selection_ = Selection::Qatzip;
  }

  for (const Buffer::RawSlice& input_slice : buffer.getRawSlices()) {
    avail_in_ = input_slice.len_;
    stream_.in = static_cast<unsigned char*>(input_slice.mem_);

    while (avail_in_ > 0) {
      process(buffer, 0);
    }

    buffer.drain(input_slice.len_);
  }

  if (state == Envoy::Compression::Compressor::State::Finish) {
    do {
      process(buffer, 1);
    } while (stream_.pending_out > 0);

    const size_t n_output = chunk_size_ - avail_out_;
    if (n_output > 0) {
      buffer.add(static_cast<void*>(chunk_char_ptr_.get()), n_output);
    }
    buffer.writeLEInt<uint32_t>(stream_.crc_32);
    buffer.writeLEInt<uint32_t>(input_len_);
  }
}

void QatzipCompressorImpl::process(Buffer::Instance& output_buffer, unsigned int last) {
  stream_.in_sz = avail_in_;
  stream_.out_sz = avail_out_;
  MonotonicTime start;
  if (fallback_state_ != nullptr) {
    start = time_source_->monotonicTime();
    if (operation_reserved_) {
      operation_reserved_ = false;
    } else {
      fallback_state_->acquire();
    }
  }
  auto status = qzCompressStream(session_, &stream_, last);
  if (fallback_state_ != nullptr) {
    fallback_state_->release(start, time_source_->monotonicTime());
  }
  // NOTE: stream_.in_sz and stream_.out_sz have changed their semantics after the call
  //       to qzCompressStream(). Despite their name the new values are consumed input
  //       and produced output (not available buffer sizes).
  avail_out_ -= stream_.out_sz;
  avail_in_ -= stream_.in_sz;
  input_len_ += stream_.in_sz;
  stream_.in = stream_.in + stream_.in_sz;
  stream_.out = stream_.out + stream_.out_sz;
  RELEASE_ASSERT(status == QZ_OK, "");
  if (avail_out_ == 0) {
    // The chunk is full, so copy it to the output buffer and reset context.
    output_buffer.add(static_cast<void*>(chunk_char_ptr_.get()), chunk_size_);
    chunk_char_ptr_ = std::make_unique<unsigned char[]>(chunk_size_);
    avail_out_ = chunk_size_;
    stream_.out = chunk_char_ptr_.get();
  }
}

} // namespace Compressor
} // namespace Qatzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
