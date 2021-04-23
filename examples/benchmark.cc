// encryption for vectors of integers...
// want to raise vector size and element type to the type level
// raise scheme to the type level too? e.g. BFV vs BGV can both do vectors of
// integers

#include <heal/heal.h>
#include <heal/backend/seal.h>

#include <algorithm>
#include <iostream>
#include <numeric>
#include <random>
#include <vector>

using namespace std;
using namespace heal;
using namespace heal::backend::seal;

#include "./stats.h"

template <typename T>
struct with_unit {
  T value;
  string unit;
};


template <typename T>
std::ostream& operator<<(std::ostream& os, with_unit<T> wu)
{
  os << wu.value << ' ' << wu.unit;
  return os;
}


class Timer {
 public:
  Timer() {
    reset();
  };

  template <typename T>
  T duration() {
    update();
    return chrono::duration_cast<T>(duration_);
  }

  void reset() {
    running_ = false;
    then_ = chrono::high_resolution_clock::now();
    duration_ = chrono::nanoseconds(0);
  }

  void start() {
    update();
    running_ = true;
  }

  void update() {
    auto now = chrono::high_resolution_clock::now();
    if (running_) {
      duration_ += chrono::duration_cast<chrono::nanoseconds>(now - then_);
    };
    then_ = now;
  }

  void stop() {
    update();
    running_ = false;
  }

 private:
  chrono::nanoseconds duration_;
  chrono::time_point<chrono::high_resolution_clock> then_;
  bool running_;
};


class Bencher {
 public:
  using results_type = map<string,with_unit<int64_t>>;

  bool loud;

  Bencher()
    : loud(false),
      prefix_(""),
      results_(new results_type())
  { }

  Bencher group(string name) {
    return Bencher(prefix_ + name + "/", *results_);
  }

  void record(string name, int64_t value, string unit) {
    string full_name = prefix_ + name;
    with_unit<int64_t> result{.value = value, .unit = unit};

    results_->emplace(full_name, result);

    if (loud) {
      cout << full_name << ": " << result << '\n';
    }
  }

  template <typename F>
  void time(string name, F f) {
    Timer t;
    // warmup...
    for (int i = 0; i < 1; i++) {
      f(t);
    }

    // TODO: run f until we have confidence in the average.
    for (int i = 0; i < 1; i++) {
      t.start();
      f(t);
      t.stop();
    }

    record(name, t.duration<chrono::nanoseconds>().count(), "ns");
  }

  const results_type& results() const {
    return *results_;
  }

 private:
  Bencher(string prefix, results_type& r)
    : prefix_(prefix),
      results_(&r)
  { }

  string prefix_;
  results_type *results_;
};


std::ostream& operator<<(std::ostream& os, const Bencher b) {
  for (auto it : b.results()) {
    os << it.first << ": " << it.second << '\n';
  }
  return os;
}


template <typename B>
void benchmark_scheme(Bencher b, const B& backend)
{
  const auto vec = backend.make_vector(1);
  const auto encoded = vec.encode();
  const auto encrypted = encoded.encrypt();

  b.time("encode", [&](Timer& t) {
    vec.encode();
  });

  b.time("decode", [&](Timer& t) {
    encoded.decode();
  });

  b.time("encrypt/vec", [&](Timer& t) {
    vec.encrypt();
  });

  b.time("encrypt/encoded", [&](Timer& t) {
    encoded.encrypt();
  });

  b.time("decrypt/vec", [&](Timer& t) {
    encrypted.decrypt();
  });

  b.time("decrypt/encoded", [&](Timer& t) {
    encrypted.decrypt_encoded();
  });
}

template <typename B>
void benchmark_relinearize(Bencher b, const B& backend)
{
    auto x1 = backend.make_vector(1).encrypt();
    auto x2 = backend.make_vector(1).encrypt();

    b.time("relinearize/3->2", [&](Timer& t) {
        t.stop();
        auto y = x1 * x2;
        t.start();
        backend.relinearize(y);
    });
}


template <typename B>
void benchmark_modulus_switch(Bencher b, const B& backend)
{
  // TODO: for each level?
  const auto x = backend.make_vector(1).encrypt();

  b.time("modulus_switch", [&](Timer& t) {
    t.stop();
    auto copy = x;
    t.start();
    backend.modulus_switch(copy);
  });
}


template <typename B>
void benchmark_multiply_depth(Bencher b, const B& backend)
{
  const auto v = backend.make_vector(1);
  const auto e1 = v.encrypt();
  auto e2 = e1 * e1;

  int depth = 0;
  while (v == e2.decrypt()) {
    depth += 1;
    e2 *= e1;
  }

  b.record("multiply_depth", depth, "ops");
}


template <typename B>
void benchmark_rotate(Bencher b, const B& backend)
{
  auto x = backend.make_vector(1).encrypt();

  b.time("rotate-by-power-of-two", [&](Timer& t) {
    x << 1;
  });
}

template <typename B>
void benchmark_arith(Bencher b, const B& backend)
{
  const auto v1 = backend.make_vector(1);
  const auto v2 = backend.make_vector(1);
  const auto e1 = v1.encrypt();
  const auto e2 = v2.encrypt();
  const auto encoded = v2.encode();

  b.time("add/vec/vec", [&](Timer& t) {
    v1 + v2;
  });

  b.time("add/encrypted/encoded", [&](Timer& t) {
    e1 + encoded;
  });

  b.time("add/encrypted/encrypted", [&](Timer& t) {
    e1 + e2;
  });

  b.time("subtract/vec/vec", [&](Timer& t) {
    v1 - v2;
  });

  b.time("subtract/encrypted/encoded", [&](Timer& t) {
    e1 - encoded;
  });

  b.time("subtract/encrypted/encrypted", [&](Timer& t) {
    e1 - e2;
  });

  b.time("multiply/vec/vec", [&](Timer& t) {
    v1 * v2;
  });

  b.time("multiply/encrypted/encoded", [&](Timer& t) {
    t.stop();
    auto copy = e1;
    t.start();
    backend.multiply(copy, encoded);
  });

  b.time("multiply/encrypted/encrypted", [&](Timer& t) {
    t.stop();
    auto copy = e1;
    t.start();
    backend.multiply(copy, e2);
  });

  b.time("inner_sum/vec", [&](Timer& t) {
    v1.inner_sum();
  });

  b.time("inner_sum/encrypted", [&](Timer& t) {
    e1.inner_sum();
  });
}

template <typename B>
void benchmark_stats(Bencher b, const B& backend)
{
  auto x = backend.make_vector();
  auto y = backend.make_vector();
  auto mask = backend.make_vector();

  random_device rd;
  mt19937 gen(rd());

  generate(x.begin(), x.end(), [&](){
    return uniform_int_distribution<>(0, 32)(gen);
  });
  generate(y.begin(), y.end(), [&](){
    return uniform_int_distribution<>(8, 24)(gen);
  });
  generate(mask.begin(), mask.end(), [&](){
    return uniform_int_distribution<>(1, 2)(gen) % 2;
  });

  auto enc_x = x.encrypt();
  auto enc_y = y.encrypt();
  auto enc_mask = mask.encrypt();

  b.time("average/vec", [&](Timer& t) {
    average<B>(x, mask);
  });

  b.time("average/enc", [&](Timer& t) {
    average<B>(enc_x, enc_mask);
  });

  b.time("variance/vec", [&](Timer& t) {
    variance<B>(x, mask);
  });

  b.time("variance/enc", [&](Timer& t) {
    variance<B>(enc_x, enc_mask);
  });

  b.time("covariance/vec", [&](Timer& t) {
    covariance<B>(x, y, mask);
  });

  b.time("covariance/enc", [&](Timer& t) {
    covariance<B>(enc_x, enc_y, enc_mask);
  });
}


void benchmark_bfv(Bencher b, size_t degree_bits)
{
  auto backend = Create(BFVOptions{
    // XXX: SEAL does not support batching or relinearization for degree 1024
    // and 2048 cyclotomic rings due to their implementation of key switching.
    // See: https://github.com/microsoft/SEAL/issues/39
    .degree = size_t(1) << degree_bits,
    .plain_modulus_bits = 12 + degree_bits,
  });

  cout << backend.options() << endl;
  benchmark_scheme(b, backend);
  benchmark_arith(b, backend);
  benchmark_rotate(b, backend);
  benchmark_relinearize(b, backend);
  benchmark_modulus_switch(b, backend);
  benchmark_multiply_depth(b, backend);
  benchmark_stats(b, backend);
}


void benchmark_ckks(Bencher b, size_t degree_bits)
{
  auto backend = Create(CKKSOptions{
    .degree = size_t(1) << degree_bits,
    .levels = 4,
    .default_scale = pow(2.0, 21),
  });

  cout << backend.options() << endl;
  benchmark_scheme(b, backend);
  benchmark_arith(b, backend);
  benchmark_rotate(b, backend);
  benchmark_relinearize(b, backend);
  benchmark_modulus_switch(b, backend);

  {
    auto x = backend.make_vector(1).encrypt();
    b.time("modulus_rescale", [&](Timer& t) {
      t.stop();
      auto copy = x;
      t.start();
      backend.modulus_rescale(copy);
    });
  }

  benchmark_stats(b, backend);
}


int main()
{
  Bencher bencher;
  bencher.loud = true;

  for (size_t degree_bits = 12; degree_bits <= 15; degree_bits += 1) {
    benchmark_bfv(bencher.group("bfv"), degree_bits);
  }
  for (size_t degree_bits = 13; degree_bits <= 15; degree_bits += 1) {
    benchmark_ckks(bencher.group("ckks"), degree_bits);
  }
  return 0;
}
