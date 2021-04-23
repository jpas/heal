#include <heal/heal.h>
#include <heal/backend/seal.h>

constexpr size_t bit_width(size_t x) noexcept
{
  size_t width = 0;
  while (x > 0) {
    width += 1;
    x >>= 1;
  }
  return width;
}

uint64_t find_plain_modulus(size_t degree, size_t min_bits) {
  while (true) {
    try {
      auto p = ::seal::PlainModulus::Batching(degree, min_bits);
      return p.value();
    } catch (std::logic_error) {
      min_bits += 1;
      continue;
    }
  }
}

namespace heal::backend::seal {

BFV Create(heal::BFVOptions options)
{
  ::seal::EncryptionParameters params(::seal::scheme_type::bfv);

  if (options.plain_modulus == 0) {
    options.plain_modulus = find_plain_modulus(
        options.degree,
        options.plain_modulus_bits
    );
  }

  options.plain_modulus_bits = bit_width(options.plain_modulus);

  params.set_poly_modulus_degree(options.degree);
  params.set_plain_modulus(options.plain_modulus);
  params.set_coeff_modulus(::seal::CoeffModulus::BFVDefault(
    options.degree,
    convert(options.security)
  ));

  return BFV(options, ::seal::SEALContext(params));
};


BFV::BFV(BFVOptions options, const ::seal::SEALContext& context)
  : options_(options),
    context_(context),
    encoder_(context),
    evaluator_(context)
{
  ::seal::KeyGenerator keygen(context);
  secret_key_ = keygen.secret_key();
  keygen.create_public_key(public_key_);
  keygen.create_relin_keys(relin_keys_);
  keygen.create_galois_keys(galois_keys_);
}


auto BFV::encode(const BFV::vector_type& src)
  const -> BFV::encoded_type
{
  BFV::encoded_type dst(*this);
  encoder_.encode(src.raw(), dst.impl_);
  return dst;
}


auto BFV::decode(const BFV::encoded_type& src)
  const -> BFV::vector_type
{
  std::vector<BFV::scalar_type> dst;
  encoder_.decode(src.impl_, dst);
  return heal::Vector<BFV>(*this, dst);
}


auto BFV::encrypt(const BFV::encoded_type& src)
  const -> BFV::encrypted_type
{
  ::seal::Encryptor e(context_, public_key_);
  BFV::encrypted_type dst(*this);
  e.encrypt(src.impl_, dst.impl_);
  return dst;
}


auto BFV::encrypt(const BFV::vector_type& src)
  const -> BFV::encrypted_type
{
  return encrypt(encode(src));
}


auto BFV::decrypt_encoded(const BFV::encrypted_type& src)
  const -> BFV::encoded_type
{
  ::seal::Decryptor d(context_, secret_key_);
  BFV::encoded_type dst(*this);
  d.decrypt(src.impl_, dst.impl_);
  return dst;
}


auto BFV::decrypt(const BFV::encrypted_type& src)
  const -> BFV::vector_type
{
  return decode(decrypt_encoded(src));
}


auto BFV::add(BFV::encrypted_type& lhs, const BFV::encrypted_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.add_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::add(BFV::encrypted_type& lhs, const BFV::encoded_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.add_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::inner_sum(BFV::encrypted_type& a)
  const -> BFV::encrypted_type&
{
  int rows = vector_size() / 2;
  for (int i = 1; i < rows; i *= 2) {
    a += a << i;
  }
  return a += ~a;
}


auto BFV::make_vector(BFV::scalar_type x)
  const -> BFV::vector_type
{
  return heal::Vector<BFV>(*this, x);
}


auto BFV::multiply(BFV::encrypted_type& lhs, const BFV::encrypted_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.multiply_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::multiply(BFV::encrypted_type& lhs, const BFV::encoded_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.multiply_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::multiply_full(
    BFV::encrypted_type& lhs,
    const BFV::encrypted_type& rhs
)
  const -> BFV::encrypted_type&
{
  return relinearize(multiply(lhs, rhs));
}


auto BFV::multiply_full(
    BFV::encrypted_type& lhs,
    const BFV::encoded_type& rhs
)
  const -> BFV::encrypted_type&
{
  return relinearize(multiply(lhs, rhs));
}


auto BFV::subtract(BFV::encrypted_type& lhs, const BFV::encrypted_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.sub_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::subtract(BFV::encrypted_type& lhs, const BFV::encoded_type& rhs)
  const -> BFV::encrypted_type&
{
  evaluator_.sub_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto BFV::rotate(BFV::encrypted_type& a, int k)
  const -> BFV::encrypted_type&
{
  evaluator_.rotate_rows_inplace(a.impl_, k, galois_keys_);
  return a;
}


auto BFV::flip(BFV::encrypted_type& a)
  const -> BFV::encrypted_type&
{
  evaluator_.rotate_columns_inplace(a.impl_, galois_keys_);
  return a;
}


auto BFV::negate(BFV::encrypted_type& a)
  const -> BFV::encrypted_type&
{
  evaluator_.negate_inplace(a.impl_);
  return a;
}


auto BFV::modulus_switch(BFV::encrypted_type& a)
  const -> BFV::encrypted_type&
{
  evaluator_.mod_switch_to_next_inplace(a.impl_);
  return a;
}

auto BFV::relinearize(BFV::encrypted_type& a)
  const -> BFV::encrypted_type&
{
  evaluator_.relinearize_inplace(a.impl_, relin_keys_);
  return a;
}


size_t BFV::vector_size() const
{
  return encoder_.slot_count();
}


template <>
Encrypted<BFV> operator~(Encrypted<BFV> a)
{
  a.backend().flip(a);
  return a;
}


} // namespace heal::backend::seal
