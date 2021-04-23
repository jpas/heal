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

  with_unit<int64_t> duration() {
    update();
    return with_unit<int64_t>{
      .value = chrono::duration_cast<chrono::nanoseconds>(duration_).count(),
      .unit = "ns",
    };
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
    with_unit<int64_t> d = t.duration();
    record(name + "/time", d.value, d.unit);
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
auto extract_at(
    size_t idx,
    const typename B::vector_type& x
) -> typename B::scalar_type
{
  return x[idx];
}


template <typename B>
auto extract_at(
    size_t idx,
    const typename B::encrypted_type& x
) -> typename B::scalar_type
{
  return x.decrypt()[idx];
}


template <typename B, typename T>
auto
average(const T& x, const T& mask)
  -> typename B::scalar_type
{
  // server side

  auto masked = x * mask;

  auto v_n = mask.inner_sum();
  auto v_sum = masked.inner_sum();

  // send v_* back to client

  auto n = extract_at<B>(0, v_n);
  auto sum = extract_at<B>(0, v_sum);

  return sum / n;
}


template <typename B, typename T>
auto
variance(const T& x, const T& mask)
  -> typename B::scalar_type
{
  // server side

  auto masked = x * mask;
  auto v_n = mask.inner_sum();
  auto v_sum = masked.inner_sum();

  auto squares = masked*masked;
  auto v_sum_of_squares = squares.inner_sum();

  // send v_* back to client

  auto n = extract_at<B>(0, v_n);
  auto sum = extract_at<B>(0, v_sum);
  auto sum_of_squares = extract_at<B>(0, v_sum_of_squares);

  auto moment1 = sum / n;
  auto moment2 = sum_of_squares / n;

  return moment2 - (moment1*moment1);
}

template <typename B>
void benchmark_scheme(Bencher b, const B& backend)
{
  const auto vec = backend.make_vector(1);
  const auto encoded = vec.encode();
  const auto encrypted = encoded.encrypt();

  b.time("encode", [&](Timer& t){
    vec.encode();
  });

  b.time("decode", [&](Timer& t){
    encoded.decode();
  });

  b.time("encrypt/vec", [&](Timer& t){
    vec.encrypt();
  });

  b.time("encrypt/encoded", [&](Timer& t){
    encoded.encrypt();
  });

  b.time("decrypt/vec", [&](Timer& t){
    encrypted.decrypt();
  });

  b.time("decrypt/encoded", [&](Timer& t){
    encrypted.decrypt_encoded();
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

  b.time("add/vec/vec", [&](Timer& t){
    v1 + v2;
  });

  b.time("add/encrypted/encoded", [&](Timer& t){
    e1 + encoded;
  });

  b.time("add/encrypted/encrypted", [&](Timer& t){
    e1 + e2;
  });

  b.time("subtract/vec/vec", [&](Timer& t){
    v1 - v2;
  });

  b.time("subtract/encrypted/encoded", [&](Timer& t){
    e1 - encoded;
  });

  b.time("subtract/encrypted/encrypted", [&](Timer& t){
    e1 - e2;
  });

  b.time("multiply/vec/vec", [&](Timer& t){
    v1 * v2;
  });

  b.time("multiply/encrypted/encoded", [&](Timer& t){
    e1 * encoded;
  });

  b.time("multiply/encrypted/encrypted", [&](Timer& t){
    e1 * e2;
  });

  b.time("inner_sum/vec", [&](Timer& t){
    v1.inner_sum();
  });

  b.time("inner_sum/encrypted", [&](Timer& t){
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
  uniform_int_distribution<> data_dist(0, 32);

  generate(x.begin(), x.end(), [&](){ return data_dist(gen); });
  generate(y.begin(), y.end(), [&](){ return data_dist(gen); });

  uniform_int_distribution<> mask_dist(1, 2);
  generate(mask.begin(), mask.end(), [&](){ return mask_dist(gen) % 2; });

  auto enc_x = x.encrypt();
  auto enc_mask = mask.encrypt();

  b.time("average/vec", [&](Timer& t){
    average<B>(x, mask);
  });

  b.time("average/enc", [&](Timer& t){
    average<B>(enc_x, enc_mask);
  });

  b.time("variance/vec", [&](Timer& t){
    variance<B>(x, mask);
  });

  b.time("variance/enc", [&](Timer& t){
    variance<B>(enc_x, enc_mask);
  });

  //benchmark_covar(b, x, y);
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

  {
    auto x1 = backend.make_vector(1).encrypt();
    auto x2 = backend.make_vector(1).encrypt();

    b.time("relinearize/3->2", [&](Timer& t){
        t.stop();
        auto copy = x1;
        t.start();
        backend.relinearize(copy);
    });
  }

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

  {
    auto x1 = backend.make_vector(1).encrypt();
    auto x2 = backend.make_vector(1).encrypt();
    backend.multiply(x1, x2);

    b.time("relinearize/3->2", [&](Timer& t){
        t.stop();
        auto copy = x1;
        t.start();
        backend.relinearize(copy);
    });

    b.time("modulus_rescale", [&](Timer& t){
        t.stop();
        auto copy = x1;
        t.start();
        backend.modulus_rescale(x1);
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
