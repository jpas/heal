#ifndef HEAL_VECTOR_H_
#define HEAL_VECTOR_H_

#include <algorithm>
#include <functional>
#include <numeric>
#include <vector>

namespace heal {

template <typename B>
class Vector {
  public:
    using scalar_type = typename B::scalar_type;

    Vector() = delete;

    Vector(const B& b)
      : backend_(&b),
        raw_(b.vector_size())
    { }

    Vector(const B& b, scalar_type x)
      : backend_(&b),
        raw_(b.vector_size(), x)
    { }

    Vector(const B& b, const std::vector<scalar_type>& v)
      : backend_(&b),
        raw_(v)
    { }

    const B& backend() const {
      return *backend_;
    }

    typename B::encoded_type encode() const {
      return backend().encode(*this);
    };

    typename B::encrypted_type encrypt() const {
      return encode().encrypt();
    };

    size_t size() const {
      return backend().vector_size();
    }

    scalar_type& operator[](ssize_t idx) {
      if (idx < 0) {
        idx = size() - idx;
      }
      return raw_[idx];
    }

    const scalar_type operator[](ssize_t idx) const {
      if (idx < 0) {
        idx = size() - idx;
      }
      return raw_[idx];
    }

    Vector<B>& operator*=(const Vector<B>& rhs) {
      for (ssize_t i = 0; i < size(); i++) {
        (*this)[i] *= rhs[i];
      }
      return *this;
    }

    Vector<B>& operator+=(const Vector<B>& rhs) {
      for (ssize_t i = 0; i < size(); i++) {
        (*this)[i] += rhs[i];
      }
      return *this;
    }

    Vector<B>& operator-=(const Vector<B>& rhs) {
      for (ssize_t i = 0; i < size(); i++) {
        (*this)[i] -= rhs[i];
      }
      return *this;
    }

    const std::vector<scalar_type>& raw() const {
      return raw_;
    }

    auto begin() {
      return raw_.begin();
    }

    auto end() {
      return raw_.end();
    }

    Vector<B> inner_sum() const {
      scalar_type sum = (*this)[0];
      for (size_t i = 1; i < size(); i++) {
        sum += (*this)[i];
      }
      return Vector<B>(backend(), sum);
    }

  private:
    const B *backend_;
    std::vector<scalar_type> raw_;
};


template <typename B>
Vector<B> operator*(Vector<B> lhs, const Vector<B>& rhs) {
  return lhs *= rhs;
}


template <typename B>
Vector<B> operator+(Vector<B> lhs, const Vector<B>& rhs) {
  return lhs += rhs;
}


template <typename B>
Vector<B> operator-(Vector<B> lhs, const Vector<B>& rhs) {
  return lhs -= rhs;
}


} // namespace heal

#endif // HEAL_VECTOR_H_
