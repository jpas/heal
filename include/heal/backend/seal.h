#pragma once

#include <heal/heal.h>
#include <seal/seal.h>


namespace heal::backend::seal {

template <typename B>
class Encrypted;

template <typename B>
class Encoded {
  friend class BFV;
  friend class CKKS;

 public:
  Encoded() = delete;
  Encoded(const B& b)
    : backend_(&b)
  { }

  inline const B& backend() const {
    return *backend_;
  }

  typename B::vector_type decode() const;

  typename B::encrypted_type encrypt() const;

 private:
  const B* backend_;
  ::seal::Plaintext impl_;
};


template <typename B>
class Encrypted {
  friend class BFV;
  friend class CKKS;

 public:
  Encrypted() = delete;
  Encrypted(const B& b)
    : backend_(&b)
  { }

  inline const B& backend() const {
    return *backend_;
  }

  typename B::vector_type decrypt() const;

  typename B::encoded_type decrypt_encoded() const;

  typename B::encrypted_type inner_sum() const;

 private:
  const B* backend_;
  ::seal::Ciphertext impl_;
};

class BFV {
  friend class Encrypted<BFV>;
  friend class Encoded<BFV>;

 public:
  using encrypted_type = Encrypted<BFV>;
  using encoded_type = Encoded<BFV>;
  using vector_type = heal::Vector<BFV>;
  using scalar_type = uint64_t;

  friend BFV Create(heal::BFVOptions options);

  auto add(encrypted_type& lhs, const encoded_type& rhs)
   const -> encrypted_type&;
  auto add(encrypted_type& lhs, const encrypted_type& rhs)
   const -> encrypted_type&;

  auto decode(const encoded_type& src)
   const -> vector_type;

  auto decrypt(const encrypted_type& src)
   const -> vector_type;

  auto decrypt_encoded(const encrypted_type& src)
    const -> encoded_type;

  auto encode(const vector_type& src)
   const -> encoded_type;

  auto encrypt(const encoded_type& src)
    const -> encrypted_type;
  auto encrypt(const vector_type& src)
    const -> encrypted_type;

  auto flip(encrypted_type& a)
   const -> encrypted_type&;

  auto make_vector(scalar_type x = 0)
   const -> vector_type;

  auto modulus_switch(encrypted_type& a)
   const -> encrypted_type&;

  auto multiply(encrypted_type& lhs, const encoded_type& rhs)
   const -> encrypted_type&;
  auto multiply(encrypted_type& lhs, const encrypted_type& rhs)
   const -> encrypted_type&;

  auto multiply_full(encrypted_type& lhs, const encoded_type& rhs)
   const -> encrypted_type&;
  auto multiply_full(encrypted_type& lhs, const encrypted_type& rhs)
   const -> encrypted_type&;

  auto negate(encrypted_type& a)
   const -> encrypted_type&;

  auto relinearize(encrypted_type& a)
   const -> encrypted_type&;

  auto rotate(encrypted_type& a, int k)
   const -> encrypted_type&;

  auto subtract(encrypted_type& lhs, const encoded_type& rhs)
    const -> encrypted_type&;
  auto subtract(encrypted_type& lhs, const encrypted_type& rhs)
    const -> encrypted_type&;

  size_t vector_size() const;

  inline const BFVOptions& options() const {
    return options_;
  }

 private:
  BFV(heal::BFVOptions options, const ::seal::SEALContext& context);

  BFVOptions options_;

  mutable ::seal::SEALContext context_;
  mutable ::seal::BatchEncoder encoder_;
  mutable ::seal::Evaluator evaluator_;

  ::seal::SecretKey secret_key_;
  ::seal::PublicKey public_key_;
  ::seal::RelinKeys relin_keys_;
  ::seal::GaloisKeys galois_keys_;
};


class CKKS {
  friend class Encrypted<CKKS>;
  friend class Encoded<CKKS>;

 public:
  using encrypted_type = Encrypted<CKKS>;
  using encoded_type = Encoded<CKKS>;
  using vector_type = heal::Vector<CKKS>;
  using scalar_type = std::complex<double>;

  friend CKKS Create(heal::CKKSOptions options);

  auto add(encrypted_type& lhs, const encoded_type& rhs)
    const -> encrypted_type&;
  auto add(encrypted_type& lhs, const encrypted_type& rhs)
    const -> encrypted_type&;

  auto assume_scale(encrypted_type& a, double c)
    const -> encrypted_type&;

  auto conjugate(encrypted_type& a)
    const -> encrypted_type&;

  auto decode(const encoded_type& src)
    const -> vector_type;

  auto decrypt(const encrypted_type& src)
    const -> vector_type;

  auto decrypt_encoded(const encrypted_type& src)
    const -> encoded_type;

  auto encode(const vector_type& src)
    const -> encoded_type;

  auto encode(const vector_type& src, double scale)
    const -> encoded_type;

  auto encrypt(const encoded_type& src)
    const -> encrypted_type;
  auto encrypt(const vector_type& src)
    const -> encrypted_type;

  auto make_vector(scalar_type x = 0)
    const -> vector_type;

  auto modulus_rescale(encrypted_type& a)
    const -> encrypted_type&;

  auto modulus_switch(encrypted_type& a)
    const -> encrypted_type&;

  auto multiply(encrypted_type& lhs, const encoded_type& rhs)
    const -> encrypted_type&;
  auto multiply(encrypted_type& lhs, const encrypted_type& rhs)
    const -> encrypted_type&;

  auto multiply_full(encrypted_type& lhs, const encoded_type& rhs)
   const -> encrypted_type&;
  auto multiply_full(encrypted_type& lhs, const encrypted_type& rhs)
   const -> encrypted_type&;

  auto negate(encrypted_type& a)
    const -> encrypted_type&;

  auto relinearize(encrypted_type& a)
    const -> encrypted_type&;

  auto rotate(encrypted_type& a, int k)
    const -> encrypted_type&;

  auto subtract(encrypted_type& lhs, const encoded_type& rhs)
    const -> encrypted_type&;
  auto subtract(encrypted_type& lhs, const encrypted_type& rhs)
    const -> encrypted_type&;

  size_t vector_size() const;

  inline const CKKSOptions& options() const {
    return options_;
  };

 private:
  CKKS(CKKSOptions options, const ::seal::SEALContext& context);

  CKKSOptions options_;

  mutable ::seal::SEALContext context_;
  mutable ::seal::CKKSEncoder encoder_;
  mutable ::seal::Evaluator evaluator_;

  ::seal::SecretKey secret_key_;
  ::seal::PublicKey public_key_;
  ::seal::RelinKeys relin_keys_;
  ::seal::GaloisKeys galois_keys_;
};


// If plain_modulus == 0, plain_modulus_bits is used to generate a suitible
// prime.
BFV Create(heal::BFVOptions options);


CKKS Create(heal::CKKSOptions options);


::seal::sec_level_type convert(heal::security security);


template <typename B>
inline typename B::vector_type Encoded<B>::decode() const {
  return backend().decode(*this);
}


template <typename B>
inline typename B::encrypted_type Encoded<B>::encrypt() const {
  return backend().encrypt(*this);
}


template <typename B>
auto Encrypted<B>::decrypt()
  const -> typename B::vector_type
{
  return backend().decrypt(*this);
}


template <typename B>
auto Encrypted<B>::decrypt_encoded()
  const -> typename B::encoded_type
{
  return backend().decrypt_encoded(*this);
}


template <typename B>
inline Encrypted<B> operator*(Encrypted<B> lhs, const Encrypted<B>& rhs)
{
  return lhs *= rhs;
}


template <typename B>
inline Encrypted<B> operator*(Encrypted<B> lhs, const Encoded<B>& rhs)
{
  return lhs *= rhs;
}


template <typename B>
inline Encrypted<B>& operator*=(Encrypted<B>& lhs, const Encrypted<B>& rhs)
{
  return lhs.backend().multiply_full(lhs, rhs);
}


template <typename B>
inline Encrypted<B>& operator*=(Encrypted<B>& lhs, const Encoded<B>& rhs)
{
  return lhs.backend().multiply_full(lhs, rhs);
}


template <typename B>
inline Encrypted<B> operator+(Encrypted<B> lhs, const Encrypted<B>& rhs)
{
  return lhs += rhs;
}


template <typename B>
inline Encrypted<B> operator+(Encrypted<B> lhs, const Encoded<B>& rhs)
{
  return lhs += rhs;
}


template <typename B>
inline Encrypted<B>& operator+=(Encrypted<B>& lhs, const Encrypted<B>& rhs)
{
  return lhs.backend().add(lhs, rhs);
}


template <typename B>
inline Encrypted<B>& operator+=(Encrypted<B>& lhs, const Encoded<B>& rhs)
{
  return lhs.backend().add(lhs, rhs);
}


template <typename B>
inline Encrypted<B> operator-(Encrypted<B> a)
{
  return a.backend().negate(a);
}


template <typename B>
inline Encrypted<B> operator-(Encrypted<B> lhs, const Encrypted<B>& rhs)
{
  return lhs -= rhs;
}


template <typename B>
inline Encrypted<B> operator-(Encrypted<B> lhs, const Encoded<B>& rhs)
{
  return lhs -= rhs;
}


template <typename B>
inline Encrypted<B>& operator-=(Encrypted<B>& lhs, const Encrypted<B>& rhs)
{
  return lhs.backend().subtract(lhs, rhs);
}


template <typename B>
inline Encrypted<B>& operator-=(Encrypted<B>& lhs, const Encoded<B>& rhs)
{
  lhs.backend().subtract(lhs, rhs);
  return lhs;
}


template <typename B>
inline Encrypted<B> operator<<(Encrypted<B> lhs, int k)
{
  return lhs <<= k;
}


template <typename B>
inline Encrypted<B>& operator<<=(Encrypted<B>& lhs, int k)
{
  return lhs.backend().rotate(lhs, k);
}


template <typename B>
inline Encrypted<B> operator>>(Encrypted<B> lhs, int k)
{
  return lhs >>= k;
}


template <typename B>
inline Encrypted<B>& operator>>=(Encrypted<B>& lhs, int k)
{
  return lhs <<= -k;
}


template <typename B>
Encrypted<B> operator~(Encrypted<B> a);


template <>
Encrypted<BFV> operator~ <>(Encrypted<BFV> a);


template <>
Encrypted<CKKS> operator~ <>(Encrypted<CKKS> a);


template <typename B>
inline Encrypted<B> inner_sum(Encrypted<B> a)
{
  return a.inner_sum();
}


template <typename B>
auto extract_at(
    size_t idx,
    const typename B::encrypted_type& x
) -> typename B::scalar_type
{
  return x.decrypt()[idx];
}


} // namespace heal::backend::seal
