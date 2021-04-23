// encryption for vectors of integers...
// want to raise vector size and element type to the type level
// raise scheme to the type level too? e.g. BFV vs BGV can both do vectors of
// integers

#include <heal/heal.h>
#include <heal/backend/seal.h>

#include <iostream>
#include <chrono>
#include <random>

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

  template <typename T = chrono::nanoseconds>
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

  ostream* os;
  chrono::seconds time_minimum;

  Bencher()
    : os(nullptr),
      prefix_(""),
      results_(new results_type())
  { }

  Bencher group(string name) {
    Bencher g = *this;
    g.prefix_ += name + "/";
    return g;
  }

  void record(string name, int64_t value, string unit) {
    string full_name = prefix_ + name;
    with_unit<int64_t> result{.value = value, .unit = unit};

    results_->emplace(full_name, result);

    if (os) {
      (*os) << full_name << ": " << result << endl;
    }
  }

  template <typename F>
  void time(string name, F f) {
    {
      // warmup to force a lazy backend.
      Timer warmup;
      f(warmup);
    }

    Timer t;
    int64_t ops = 0;
    do {
      ops += 1;
      t.start();
      f(t);
      t.stop();
    } while (t.duration() < time_minimum);

    int64_t ns_per_op = t.duration<chrono::nanoseconds>().count() / ops;
    record(name + "/time", ns_per_op, "ns/op");
    record(name + "/ops", ops, "ops");
  }

  const results_type& results() const {
    return *results_;
  }

 private:
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

  b.time("encode(vector)", [&](Timer& t) {
    vec.encode();
  });

  b.time("decode(encoded)", [&](Timer& t) {
    encoded.decode();
  });

  b.time("encrypt(vector)", [&](Timer& t) {
    vec.encrypt();
  });

  b.time("encrypt(encoded)", [&](Timer& t) {
    encoded.encrypt();
  });

  b.time("decrypt()", [&](Timer& t) {
    encrypted.decrypt();
  });

  b.time("decrypt_encoded()", [&](Timer& t) {
    encrypted.decrypt_encoded();
  });
}

template <typename B>
void benchmark_relinearize(Bencher b, const B& backend)
{
  auto x = backend.make_vector(1).encrypt();
  auto y = backend.make_vector(1).encrypt();
  backend.multiply_no_maintainance(x, y);

  b.time("relinearize(encrypted)", [&](Timer& t) {
    t.stop();
    auto copy = x;
    t.start();
    backend.relinearize(copy);
  });
}


template <typename B>
void benchmark_modulus_switch(Bencher b, const B& backend)
{
  // TODO: for each level?
  auto x = backend.make_vector(1).encrypt();

  b.time("modulus_switch(encrypted)", [&](Timer& t) {
    t.stop();
    auto copy = x;
    t.start();
    backend.modulus_switch(copy);
  });
}


template <typename B>
void benchmark_maximum_depth(Bencher b, const B& backend)
{
  const auto v = backend.make_vector(1);
  const auto e1 = v.encrypt();
  auto e2 = e1 * e1;

  int depth = 0;
  while (v == e2.decrypt()) {
    depth += 1;
    e2 *= e1;
  }

  b.record("maximum_depth", depth, "ops");
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
void benchmark_arithmetic(Bencher b, const B& backend)
{
  const auto v1 = backend.make_vector(1);
  const auto v2 = backend.make_vector(1);
  const auto e1 = v1.encrypt();
  const auto e2 = v2.encrypt();
  const auto encoded = v2.encode();

  b.time("add(vector,vector)", [&](Timer& t) {
    v1 + v2;
  });

  b.time("add(encrypted,encoded)", [&](Timer& t) {
    e1 + encoded;
  });

  b.time("add(encrypted,encrypted)", [&](Timer& t) {
    e1 + e2;
  });

  b.time("subtract(vector,vector)", [&](Timer& t) {
    v1 - v2;
  });

  b.time("subtract(encrypted,encoded)", [&](Timer& t) {
    e1 - encoded;
  });

  b.time("subtract(encrypted,encrypted)", [&](Timer& t) {
    e1 - e2;
  });

  b.time("multiply(vector,vector)", [&](Timer& t) {
    v1 * v2;
  });

  b.time("multiply(encrypted,encoded)", [&](Timer& t) {
    t.stop();
    auto copy = e1;
    t.start();
    backend.multiply_no_maintainance(copy, encoded);
  });

  b.time("multiply(encrypted,encrypted)", [&](Timer& t) {
    t.stop();
    auto copy = e1;
    t.start();
    backend.multiply_no_maintainance(copy, e2);
  });

  b.time("inner_sum(vector)", [&](Timer& t) {
    v1.inner_sum();
  });

  b.time("inner_sum(encrypted)", [&](Timer& t) {
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

  b.time("average(vector)", [&](Timer& t) {
    average<B>(x, mask);
  });

  b.time("average(encrypted)", [&](Timer& t) {
    average<B>(enc_x, enc_mask);
  });

  b.time("variance(vector)", [&](Timer& t) {
    variance<B>(x, mask);
  });

  b.time("variance(encrypted)", [&](Timer& t) {
    variance<B>(enc_x, enc_mask);
  });

  b.time("covariance(vector)", [&](Timer& t) {
    covariance<B>(x, y, mask);
  });

  b.time("covariance(encrypted)", [&](Timer& t) {
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

  benchmark_scheme(b, backend);
  benchmark_arithmetic(b, backend);
  benchmark_rotate(b, backend);
  benchmark_relinearize(b, backend);
  benchmark_modulus_switch(b, backend);
  benchmark_maximum_depth(b, backend);
  benchmark_stats(b, backend);
}


void benchmark_ckks(Bencher b, size_t degree_bits)
{
  auto backend = Create(CKKSOptions{
    .degree = size_t(1) << degree_bits,
    .levels = 4,
    .default_scale = pow(2.0, 21),
  });

  benchmark_scheme(b, backend);
  benchmark_arithmetic(b, backend);
  benchmark_rotate(b, backend);
  benchmark_relinearize(b, backend);
  benchmark_modulus_switch(b, backend);

  {
    auto x = backend.make_vector(1).encrypt();
    b.time("modulus_rescale(encrypted)", [&](Timer& t) {
      t.stop();
      auto copy = x;
      t.start();
      backend.modulus_rescale(copy);
    });
  }

  benchmark_stats(b, backend);
}

int main(int argc, char *argv[])
{
  Bencher bencher;
  bencher.os = &cout;
  bencher.time_minimum = chrono::seconds(1);

  size_t max_degree_bits = 15;

  for (size_t bits = 12; bits <= max_degree_bits; bits += 1) {
    string id = "bfv/" + to_string(1 << bits);
    benchmark_bfv(bencher.group(id), bits);
  }

  for (size_t bits = 13; bits <= max_degree_bits; bits += 1) {
    string id = "ckks/" + to_string(1 << bits);
    benchmark_ckks(bencher.group(id), bits);
  }

  return 0;
}
