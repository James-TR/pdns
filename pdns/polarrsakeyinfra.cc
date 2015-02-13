#include <polarssl/ecdsa.h>
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <sha.hh>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/foreach.hpp>
#include "dnssecinfra.hh"
using namespace boost::assign;

class ECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit ECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  
  ~ECDSADNSCryptoKeyEngine() {}
  // XXX FIXME NEEDS DEEP COPY CONSTRUCTOR SO WE DON'T SHARE KEYS
  string getName() const { return "PolarSSL ECDSA"; }
  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new ECDSADNSCryptoKeyEngine(algorithm);
  }

private:
  static EC_Domain_Params getECParams(unsigned int algorithm);
  shared_ptr<ECDSA_PrivateKey> d_key;
  shared_ptr<ECDSA_PublicKey> d_pubkey;
};

EC_Domain_Params ECDSADNSCryptoKeyEngine::getECParams(unsigned int algorithm) 
{
  if(algorithm==13)
    return EC_Domain_Params("1.2.840.10045.3.1.7");
  else if(algorithm == 14)
    return EC_Domain_Params("1.3.132.0.34");
  else
    throw runtime_error("Requested for unknown EC domain parameters for algorithm "+lexical_cast<string>(algorithm));
}

void ECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  EC_Domain_Params params;
  if(bits==256) {
    params = getECParams(13);
  } 
  else if(bits == 384){
    params = getECParams(14);
  }
  else {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ECDSA class");
  }
  d_key = shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, params));
}

int ECDSADNSCryptoKeyEngine::getBits() const
{
  if(d_algorithm == 13)
    return 256;
  else if(d_algorithm == 14)
    return 384;
  return -1;
}

DNSCryptoKeyEngine::storvector_t ECDSADNSCryptoKeyEngine::convertToISCVector() const
{
  /* Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  storvector_t storvect;
  
  string algorithm;
  if(getBits()==256) 
    algorithm = "13 (ECDSAP256SHA256)";
  else if(getBits()==384) 
    algorithm ="14 (ECDSAP384SHA384)";
  else 
    algorithm =" ? (?)";
  storvect.push_back(make_pair("Algorithm", algorithm));
  
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  storvect.push_back(make_pair("PrivateKey", string((char*)&*buffer.begin(), (char*)&*buffer.end())));
  
  return storvect;
}

void ECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if(drc.d_algorithm != d_algorithm) 
    throw runtime_error("Tried to feed an algorithm "+lexical_cast<string>(drc.d_algorithm)+" to a "+lexical_cast<string>(d_algorithm)+" key!");
  string privateKey=stormap["privatekey"];
  
  BigInt bigint((byte*)privateKey.c_str(), privateKey.length());
  EC_Domain_Params params=getECParams(d_algorithm);
  AutoSeeded_RNG rng;

  d_key=shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, params, bigint));
}

std::string ECDSADNSCryptoKeyEngine::getPubKeyHash() const 
{
  const BigInt&x = d_key->private_value();   // um, this is not the 'pubkeyhash', ahu
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string ECDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  const BigInt&x =d_key->public_point().get_affine_x();
  const BigInt&y =d_key->public_point().get_affine_y();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
  MemoryVector<byte> bits(2*part_size);
  
  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);
  return string((const char*)bits.begin(), (const char*)bits.end());
}

void ECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string&input) 
{
  BigInt x, y;
  
  x.binary_decode((const byte*)input.c_str(), input.length()/2);
  y.binary_decode((const byte*)input.c_str() + input.length()/2, input.length()/2);

  EC_Domain_Params params=getECParams(d_algorithm);
  PointGFp point(params.get_curve(), x,y);
  d_pubkey = shared_ptr<ECDSA_PublicKey>(new ECDSA_PublicKey(params, point));
  d_key.reset();
}


std::string ECDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);
  ECDSA_Signature_Operation ops(*d_key);
  AutoSeeded_RNG rng;
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);
  
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string ECDSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  if(getBits() == 256) { // SHA256
    SHA_256 hasher;
    result= hasher.process(orig);
  }
  else { // SHA384
    SHA_384 hasher;
    result = hasher.process(orig);
  }
  
  return string((const char*)result.begin(), (const char*) result.end());
}

bool ECDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  ECDSA_PublicKey* key;
  if(d_key)
    key = d_key.get();
  else
    key = d_pubkey.get();
  ECDSA_Verification_Operation ops(*key);
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
}

#define PDNSSEC_MI(x) mpi_init(&d_context.x)
#define PDNSSEC_MC(x) PDNSSEC_MI(x); mpi_copy(&d_context.x, const_cast<mpi*>(&orig.d_context.x))
#define PDNSSEC_MF(x) mpi_free(&d_context.x)

class RSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  string getName() const { return "PolarSSL RSA"; }

  explicit RSADNSCryptoKeyEngine(unsigned int algorithm) : DNSCryptoKeyEngine(algorithm)
  {
    memset(&d_context, 0, sizeof(d_context));
    PDNSSEC_MI(N); 
    PDNSSEC_MI(E); PDNSSEC_MI(D); PDNSSEC_MI(P); PDNSSEC_MI(Q); PDNSSEC_MI(DP); PDNSSEC_MI(DQ); PDNSSEC_MI(QP); PDNSSEC_MI(RN); PDNSSEC_MI(RP); PDNSSEC_MI(RQ);
  }

  ~RSADNSCryptoKeyEngine()
  {
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
  }

  bool operator<(const RSADNSCryptoKeyEngine& rhs) const
  {
    return tie(d_context.N, d_context.E, d_context.D, d_context.P, d_context.Q, d_context.DP, d_context.DQ, d_context.QP)
    < tie(rhs.d_context.N, rhs.d_context.E, rhs.d_context.D, rhs.d_context.P, rhs.d_context.Q, rhs.d_context.DP, rhs.d_context.DQ, rhs.d_context.QP);
  }

  RSADNSCryptoKeyEngine(const RSADNSCryptoKeyEngine& orig) : DNSCryptoKeyEngine(orig.d_algorithm)
  {
    // this part is a little bit scary.. we make a 'deep copy' of an RSA state, and polarssl isn't helping us so we delve into thr struct
    d_context.ver = orig.d_context.ver; 
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
  }

  RSADNSCryptoKeyEngine& operator=(const RSADNSCryptoKeyEngine& orig) 
  {
    *this = RSADNSCryptoKeyEngine(orig);
    return *this;
  }

  const rsa_context& getConstContext() const
  {
    return d_context;
  }

  rsa_context& getContext() 
  {
    return d_context;
  }

  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const
  {
    return mpi_size(&d_context.N)*8;
  }
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
  void fromPublicKeyString(const std::string& raw);
  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new RSADNSCryptoKeyEngine(algorithm);
  }

private:
  rsa_context d_context;
};

// see above
#undef PDNSSEC_MC
#undef PDNSSEC_MI
#undef PDNSSEC_MF


inline bool operator<(const mpi& a, const mpi& b)
{
  return mpi_cmp_mpi(&a, &b) < 0;
}


void RSADNSCryptoKeyEngine::create(unsigned int bits)
{
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  
  entropy_init( &entropy );
  int ret=ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (unsigned char *) "PowerDNS", 8);
  if(ret < 0) 
    throw runtime_error("Entropy gathering for key generation failed");
  rsa_init(&d_context, RSA_PKCS_V15, 0); // FIXME this leaks memory (it does?)
  ret=rsa_gen_key(&d_context, ctr_drbg_random, &ctr_drbg, bits, 65537);
  if(ret < 0) 
    throw runtime_error("Key generation failed");
}

std::string RSADNSCryptoKeyEngine::getPubKeyHash() const
{
  unsigned char hash[20];
  unsigned char N[mpi_size(&d_context.N)];
  mpi_write_binary(&d_context.N, N, sizeof(N));
  unsigned char E[mpi_size(&d_context.E)];
  mpi_write_binary(&d_context.E, E, sizeof(E));
  
  sha1_context ctx;
  sha1_starts(&ctx);
  sha1_update(&ctx, N, sizeof(N));
  sha1_update(&ctx, E, sizeof(E));
  sha1_finish(&ctx, hash);
  return string((char*)hash, sizeof(hash));
}

std::string RSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);
  unsigned char signature[mpi_size(&d_context.N)];
  md_type_t hashKind;

  if(hash.size()==20)
    hashKind= SIG_RSA_SHA1;
  else if(hash.size()==32) 
    hashKind= SIG_RSA_SHA256;
  else
    hashKind = SIG_RSA_SHA512;
  
  int ret=rsa_pkcs1_sign(const_cast<rsa_context*>(&d_context), NULL, NULL, RSA_PRIVATE, 
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  return string((char*) signature, sizeof(signature));
}

bool RSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  md_type_t hashKind;
  string hash=this->hash(msg);
  if(hash.size()==20)
    hashKind= SIG_RSA_SHA1;
  else if(hash.size()==32) 
    hashKind= SIG_RSA_SHA256;
  else
    hashKind = SIG_RSA_SHA512;
  
  int ret=rsa_pkcs1_verify(const_cast<rsa_context*>(&d_context),
#if POLARSSL_VERSION_NUMBER >= 0x01020900
    NULL, NULL,
#endif
    RSA_PUBLIC,
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), (unsigned char*) signature.c_str());
  
  return ret==0; // 0 really IS ok ;-)
}

std::string RSADNSCryptoKeyEngine::hash(const std::string& toHash) const
{
  if(d_algorithm <= 7 ) {  // RSASHA1
    unsigned char hash[20];
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 8) { // RSASHA256
    unsigned char hash[32];
#if POLARSSL_VERSION_NUMBER >= 0x01030000
    sha256((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
#else
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
#endif
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 10) { // RSASHA512
    unsigned char hash[64];
#if POLARSSL_VERSION_NUMBER >= 0x01030000
    sha512((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
#else
    sha4((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
#endif
    return string((char*)hash, sizeof(hash));
  }
  throw runtime_error("PolarSSL hashing method can't hash algorithm "+lexical_cast<string>(d_algorithm));
}


DNSCryptoKeyEngine::storvector_t RSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  typedef vector<pair<string, const mpi*> > outputs_t;
  outputs_t outputs;
  push_back(outputs)("Modulus", &d_context.N)("PublicExponent",&d_context.E)
    ("PrivateExponent",&d_context.D)
    ("Prime1",&d_context.P)
    ("Prime2",&d_context.Q)
    ("Exponent1",&d_context.DP)
    ("Exponent2",&d_context.DQ)
    ("Coefficient",&d_context.QP);

  string algorithm=lexical_cast<string>(d_algorithm);
  switch(d_algorithm) {
    case 5:
    case 7 :
      algorithm+= " (RSASHA1)";
      break;
    case 8:
      algorithm += " (RSASHA256)";
      break;
  }
  storvect.push_back(make_pair("Algorithm", algorithm));

  BOOST_FOREACH(outputs_t::value_type value, outputs) {
    unsigned char tmp[mpi_size(value.second)];
    mpi_write_binary(value.second, tmp, sizeof(tmp));
    storvect.push_back(make_pair(value.first, string((char*)tmp, sizeof(tmp))));
  }
  return storvect;
}


void RSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc,  std::map<std::string, std::string>& stormap)
{
  string sline;
  string key,value;
  typedef map<string, mpi*> places_t;
  places_t places;
  
  rsa_init(&d_context, RSA_PKCS_V15, 0);

  places["Modulus"]=&d_context.N;
  places["PublicExponent"]=&d_context.E;
  places["PrivateExponent"]=&d_context.D;
  places["Prime1"]=&d_context.P;
  places["Prime2"]=&d_context.Q;
  places["Exponent1"]=&d_context.DP;
  places["Exponent2"]=&d_context.DQ;
  places["Coefficient"]=&d_context.QP;
  
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  
  string raw;
  BOOST_FOREACH(const places_t::value_type& val, places) {
    raw=stormap[toLower(val.first)];
    mpi_read_binary(val.second, (unsigned char*) raw.c_str(), raw.length());
  }

  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does
  drc.d_key = this->getPublicKeyString();
  drc.d_protocol=3;
}

void RSADNSCryptoKeyEngine::fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  vector<string> integers;
  decodeDERIntegerSequence(raw, integers);
  cerr<<"Got "<<integers.size()<<" integers"<<endl; 
  map<int, mpi*> places;
  
  rsa_init(&d_context, RSA_PKCS_V15, 0);

  places[1]=&d_context.N;
  places[2]=&d_context.E;
  places[3]=&d_context.D;
  places[4]=&d_context.P;
  places[5]=&d_context.Q;
  places[6]=&d_context.DP;
  places[7]=&d_context.DQ;
  places[8]=&d_context.QP;

  string modulus, exponent;
  
  for(int n = 0; n < 9 ; ++n) {
    if(places.count(n)) {
      if(places[n]) {
        mpi_read_binary(places[n], (const unsigned char*)integers[n].c_str(), integers[n].length());
        if(n==1)
          modulus=integers[n];
        if(n==2)
          exponent=integers[n];
      }
    }
  }
  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does

  if(exponent.length() < 255) 
    drc.d_key.assign(1, (char) (unsigned int) exponent.length());
  else {
    drc.d_key.assign(1, 0);
    uint16_t len=htons(exponent.length());
    drc.d_key.append((char*)&len, 2);
  }
  drc.d_key.append(exponent);
  drc.d_key.append(modulus);
  drc.d_protocol=3;
}

void RSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& rawString)
{
  rsa_init(&d_context, RSA_PKCS_V15, 0);
  string exponent, modulus;
  const unsigned char* raw = (const unsigned char*)rawString.c_str();
  
  if(raw[0] != 0) {
    exponent=rawString.substr(1, raw[0]);
    modulus=rawString.substr(raw[0]+1);
  } else {
    exponent=rawString.substr(3, raw[1]*0xff + raw[2]);
    modulus = rawString.substr(3+ raw[1]*0xff + raw[2]);
  }
  mpi_read_binary(&d_context.E, (unsigned char*)exponent.c_str(), exponent.length());   
  mpi_read_binary(&d_context.N, (unsigned char*)modulus.c_str(), modulus.length());    
  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does
}

string RSADNSCryptoKeyEngine::getPublicKeyString()  const
{
  string keystring;
  char tmp[std::max(mpi_size(&d_context.E), mpi_size(&d_context.N))];

  mpi_write_binary(&d_context.E, (unsigned char*)tmp, mpi_size(&d_context.E) );
  string exponent((char*)tmp, mpi_size(&d_context.E));

  mpi_write_binary(&d_context.N, (unsigned char*)tmp, mpi_size(&d_context.N) );
  string modulus((char*)tmp, mpi_size(&d_context.N));

  if(exponent.length() < 255) 
    keystring.assign(1, (char) (unsigned int) exponent.length());
  else {
    keystring.assign(1, 0);
    uint16_t len=htons(exponent.length());
    keystring.append((char*)&len, 2);
  }
  keystring.append(exponent);
  keystring.append(modulus);
  return keystring;
}

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSCryptoKeyEngine::report(5, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(7, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(8, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(10, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(13, &ECDSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(14, &ECDSADNSCryptoKeyEngine::maker, true);
  }
} loaderPolar;
}

