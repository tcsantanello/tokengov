#ifndef __OSSLPROVIDER_H_
#define __OSSLPROVIDER_H_

#include "token/api.hh"
#include <arpa/inet.h>
#include <memory.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
HMAC_CTX *HMAC_CTX_new( void ) {
  HMAC_CTX *ctx = reinterpret_cast< HMAC_CTX * >( OPENSSL_malloc( sizeof( *ctx ) ) );
  if ( ctx ) {
    HMAC_CTX_init( ctx );
  }
  return ctx;
}

void HMAC_CTX_free( HMAC_CTX *ctx ) {
  if ( ctx ) {
    HMAC_CTX_cleanup( ctx );
    OPENSSL_free( ctx );
  }
}
#endif

class OpenSSLEncKey : public token::crypto::interface::EncKey {
  using bytea = token::crypto::bytea;

 public:
  explicit OpenSSLEncKey( std::string _name )
    : key( "" )
    , iv( "" )
    , name( std::move( _name ) )
    , cipher( EVP_aes_256_cbc( ) )
    , block_size( EVP_CIPHER_block_size( cipher ) )
    , iv_len( EVP_CIPHER_iv_length( cipher ) )
    , key_len( EVP_CIPHER_key_length( cipher ) ) {
    fillValue( key, sizeof( key ), key_len );
    fillValue( iv, sizeof( iv ), iv_len );
  }

  bytea transform( const bytea &data, bool encrypt ) const {
    auto    ctx = std::shared_ptr< EVP_CIPHER_CTX >( EVP_CIPHER_CTX_new( ), EVP_CIPHER_CTX_free );
    uint8_t inBlock[ block_size ];
    uint8_t outBlock[ block_size ];
    bytea   rc;
    int     length = 0;

    EVP_CipherInit( ctx.get( ), cipher, key, iv, encrypt ? 1 : 0 );

    for ( bytea::size_type pos = 0; pos < data.size( ); pos += block_size ) {
      memcpy( inBlock, &data[ pos ], std::min( data.size( ) - pos, block_size ) );

      EVP_CipherUpdate( ctx.get( ), outBlock, &length, inBlock, block_size );

      rc.insert( rc.end( ), outBlock, outBlock + length );
    }

    EVP_CipherFinal( ctx.get( ), outBlock, &length );

    rc.insert( rc.end( ), outBlock, outBlock + length );

    return rc;
  }

  bytea encrypt( const bytea data ) const override {
    union {
      uint32_t len;
      uint8_t  bytes[ 0 ];
    } header = { htonl( ( uint32_t ) data.size( ) ) };
    bytea packet;

    packet.insert( packet.end( ), header.bytes, header.bytes + sizeof( header ) );
    packet.insert( packet.end( ), data.begin( ), data.end( ) );

    return transform( packet, true );
  }

  bytea decrypt( const bytea data ) const override {
    auto     packet = transform( data, false );
    uint32_t len    = ntohl( *( uint32_t * ) &packet[ 0 ] );

    return bytea( packet.begin( ) + sizeof( len ), packet.begin( ) + sizeof( len ) + len );
  }

  explicit operator std::string( ) override { return name; }

 private:
  void fillValue( uint8_t *block, size_t length, size_t size ) {
    for ( size_t pos = 0; size > pos; pos += SHA_DIGEST_LENGTH ) {
      SHA_CTX ctx                         = { 0 };
      uint8_t digest[ SHA_DIGEST_LENGTH ] = "";

      SHA1_Init( &ctx );
      SHA1_Update( &ctx, block, length - pos );
      SHA1_Update( &ctx, name.c_str( ), name.size( ) );
      SHA1_Final( digest, &ctx );

      memcpy( block + pos, digest, std::min( ( size_t ) SHA_DIGEST_LENGTH, length - pos ) );
    }
  }

  uint8_t           key[ EVP_MAX_KEY_LENGTH ];
  uint8_t           iv[ EVP_MAX_IV_LENGTH ];
  std::string       name;
  const EVP_CIPHER *cipher;
  const size_t      block_size;
  const size_t      iv_len;
  const size_t      key_len;
};

class OpenSSLMacKey : public token::crypto::interface::MacKey {
  using bytea = token::crypto::bytea;

 public:
  explicit OpenSSLMacKey( std::string _name )
    : key( "" )
    , name( std::move( _name ) )
    , md( EVP_sha512( ) )
    , mdSize( EVP_MD_size( md ) ) {
    fillValue( key, sizeof( key ), mdSize );
  }

  bytea hash( const bytea &data ) const override {
    auto    digestLength = ( unsigned int ) 0;
    auto    ctx          = std::shared_ptr< HMAC_CTX >( HMAC_CTX_new( ), HMAC_CTX_free );
    uint8_t digest[ HMAC_MAX_MD_CBLOCK ] = "";
    bytea   rc;

    HMAC_Init_ex( ctx.get( ), key, mdSize, md, nullptr );
    HMAC_Update( ctx.get( ), &data[ 0 ], data.size( ) );
    HMAC_Final( ctx.get( ), digest, &digestLength );

    rc.insert( rc.end( ), digest, digest + digestLength );

    return rc;
  }

  explicit operator std::string( ) override { return name; }

 private:
  void fillValue( uint8_t *block, size_t length, size_t size ) {
    for ( size_t pos = 0; size > pos; pos += SHA_DIGEST_LENGTH ) {
      SHA_CTX ctx                         = { 0 };
      uint8_t digest[ SHA_DIGEST_LENGTH ] = "";

      SHA1_Init( &ctx );
      SHA1_Update( &ctx, block, length - pos );
      SHA1_Update( &ctx, name.c_str( ), name.size( ) );
      SHA1_Final( digest, &ctx );

      memcpy( block + pos, digest, std::min( ( size_t ) SHA_DIGEST_LENGTH, length - pos ) );
    }
  }

  uint8_t       key[ HMAC_MAX_MD_CBLOCK ];
  std::string   name;
  const EVP_MD *md;
  const size_t  mdSize;
};

class OpenSSLProvider : public token::crypto::Provider {

  token::crypto::EncKey getEncKey( std::string name ) override {
    return std::make_shared< OpenSSLEncKey >( name );
  }

  token::crypto::MacKey getMacKey( std::string name ) override {
    return std::make_shared< OpenSSLMacKey >( name );
  }

  void random( void *block, size_t length ) override {
    if ( randomize ) {
      RAND_bytes( ( uint8_t * ) block, length );
    } else {
      memset( block, 0x00, length );
    }

    if ( !randomize ) {
      if ( --cycle == 0 ) {
        randomize = true;
      }
    }
  }

  explicit operator std::string( ) override { return "OpenSSL"; }

 public:
  static bool randomize;
  static int  cycle;
};

#endif // __OSSLPROVIDER_H_
