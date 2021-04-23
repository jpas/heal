#include <heal/heal.h>
#include <heal/backend/seal.h>

#include <cmath>

namespace heal::backend::seal {


CKKS Create(heal::CKKSOptions options) {
  ::seal::EncryptionParameters params(::seal::scheme_type::ckks);
  params.set_poly_modulus_degree(options.degree);

  // SEAL likes it when the first and last moduli are 60 bits each, so we will
  // use the remaining bits to figure out bits for the intermediate moduli.
  // Figuring out a balance for lower degrees is too much work at the moment
  int max_bits = ::seal::CoeffModulus::MaxBitCount(
    options.degree,
    convert(options.security)
  );
  int bits_each = trunc(log2(options.default_scale));
  int bits_extra = (max_bits - options.levels*bits_each) / 2;
  int bits_special = std::min(60, bits_each + bits_extra);

  // make the first and last moduli as large as possible
  std::vector<int> bit_sizes(options.levels, bits_each);
  bit_sizes[0] = bits_special;
  bit_sizes[options.levels-1] = bits_special;

  params.set_coeff_modulus(::seal::CoeffModulus::Create(
    options.degree,
    bit_sizes
  ));

  return CKKS(options, ::seal::SEALContext(params));
};


CKKS::CKKS(CKKSOptions options, const ::seal::SEALContext& context)
  : options_(options),
    context_(context),
    encoder_(context),
    evaluator_(context) {
  ::seal::KeyGenerator keygen(context);
  secret_key_ = keygen.secret_key();
  keygen.create_public_key(public_key_);
  keygen.create_relin_keys(relin_keys_);
  keygen.create_galois_keys(galois_keys_);
}


auto CKKS::add(CKKS::encrypted_type& lhs, const CKKS::encrypted_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.add_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto CKKS::add(CKKS::encrypted_type& lhs, const CKKS::encoded_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.add_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto CKKS::assume_scale(CKKS::encrypted_type& a, double scale)
  const -> CKKS::encrypted_type&
{
  a.impl_.scale() = scale;
  return a;
}


auto CKKS::conjugate(CKKS::encrypted_type& a)
  const -> CKKS::encrypted_type&
{
  evaluator_.complex_conjugate_inplace(a.impl_, galois_keys_);
  return a;
}


auto CKKS::decode(const CKKS::encoded_type& src)
  const -> CKKS::vector_type
{
  std::vector<CKKS::scalar_type> dst;
  encoder_.decode(src.impl_, dst);
  return heal::Vector<CKKS>(*this, dst);
}


auto CKKS::decrypt_encoded(const CKKS::encrypted_type& src)
  const -> CKKS::encoded_type
{
  ::seal::Decryptor d(context_, secret_key_);
  CKKS::encoded_type dst(*this);
  d.decrypt(src.impl_, dst.impl_);
  return dst;
}


auto CKKS::decrypt(const CKKS::encrypted_type& src)
  const -> CKKS::vector_type
{
  return decode(decrypt_encoded(src));
}


auto CKKS::encode(const CKKS::vector_type& src)
  const -> CKKS::encoded_type
{
  CKKS::encoded_type dst(*this);
  encoder_.encode(src.raw(), options().default_scale, dst.impl_);
  return dst;
}


auto CKKS::encode(const CKKS::vector_type& src, double scale)
  const -> CKKS::encoded_type
{
  CKKS::encoded_type dst(*this);
  encoder_.encode(src.raw(), scale, dst.impl_);
  return dst;
}


auto CKKS::encrypt(const CKKS::encoded_type& src)
  const -> CKKS::encrypted_type
{
  ::seal::Encryptor e(context_, public_key_);
  CKKS::encrypted_type dst(*this);
  e.encrypt(src.impl_, dst.impl_);
  return dst;
}


auto CKKS::encrypt(const CKKS::vector_type& src)
  const -> CKKS::encrypted_type
{
  return encrypt(encode(src));
}


auto CKKS::make_vector(CKKS::scalar_type x)
  const -> CKKS::vector_type
{
  return heal::Vector(*this, x);
}


auto CKKS::modulus_rescale(CKKS::encrypted_type& a)
  const -> CKKS::encrypted_type&
{
  evaluator_.rescale_to_next_inplace(a.impl_);
  return a;
}


auto CKKS::modulus_switch(CKKS::encrypted_type& a)
  const -> CKKS::encrypted_type&
{
  evaluator_.mod_switch_to_next_inplace(a.impl_);
  return a;
}


auto CKKS::multiply(CKKS::encrypted_type& lhs, const CKKS::encrypted_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.multiply_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto CKKS::multiply(CKKS::encrypted_type& lhs, const CKKS::encoded_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.multiply_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto CKKS::multiply_full(
  CKKS::encrypted_type& lhs,
  const CKKS::encrypted_type& rhs
)
  const -> CKKS::encrypted_type&
{
  return modulus_rescale(relinearize(multiply(lhs, rhs)));
}


auto CKKS::multiply_full(
  CKKS::encrypted_type& lhs,
  const CKKS::encoded_type& rhs
)
  const -> CKKS::encrypted_type&
{
  return modulus_rescale(multiply(lhs, rhs));
}


auto CKKS::negate(CKKS::encrypted_type& a)
  const -> CKKS::encrypted_type&
{
  evaluator_.negate_inplace(a.impl_);
  return a;
}


auto CKKS::rotate(CKKS::encrypted_type& a, int k)
  const -> CKKS::encrypted_type&
{
  evaluator_.rotate_vector_inplace(a.impl_, k, galois_keys_);
  return a;
}


auto CKKS::relinearize(CKKS::encrypted_type& a)
  const -> CKKS::encrypted_type&
{
  evaluator_.relinearize_inplace(a.impl_, relin_keys_);
  return a;
}


auto CKKS::subtract(CKKS::encrypted_type& lhs, const CKKS::encrypted_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.sub_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


auto CKKS::subtract(CKKS::encrypted_type& lhs, const CKKS::encoded_type& rhs)
  const -> CKKS::encrypted_type&
{
  evaluator_.sub_plain_inplace(lhs.impl_, rhs.impl_);
  return lhs;
}


size_t CKKS::vector_size() const {
  return encoder_.slot_count();
}


template <>
Encrypted<CKKS> operator~(Encrypted<CKKS> a)
{
  a.backend().conjugate(a);
  return a;
}


template <>
Encrypted<CKKS> Encrypted<CKKS>::inner_sum() const
{
  Encrypted<CKKS> out = *this;
  for (int i = 1; i < backend().vector_size(); i *= 2) {
    out += out << i;
  }
  return out;
}


} // namespace heal::backend::seal
