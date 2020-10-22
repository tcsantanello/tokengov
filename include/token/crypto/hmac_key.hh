
#ifndef __TOKENIZATION_HMAC_KEY_HH__
#define __TOKENIZATION_HMAC_KEY_HH__

#include "token/crypto/base.hh"
#include <memory>
#include <string>

namespace token {
  namespace crypto {
    namespace interface {
      /** HMAC key interface */
      struct MacKey {
        /**
         * @brief Hash a string
         * @param data string to hash
         * @return hash byte sequence
         */
        bytea hash( const std::string &data ) const {
          bytea bytes{ data.begin( ), data.end( ) };
          return hash( bytes );
        }

        /**
         * @brief Hash a sequence of bytes
         * @param data byte sequence
         * @return hash byte sequence
         */
        virtual bytea hash( const bytea &data ) const = 0;

        /**
         * @brief Verify the hash
         * @param data input data
         * @param hash comparison hash
         * @return true on match, false if not
         */
        bool verify( const bytea &data, const bytea &hash ) const {
          auto computed = this->hash( data );

          if ( computed.size( ) != hash.size( ) ) {
            return false;
          }

          return std::equal( computed.begin( ), computed.end( ), hash.begin( ) );
        }

        /**
         * @brief String representation of the key (e.g. key name)
         * @return string representation
         */
        virtual explicit operator std::string( ) { return ""; };
      };
    } // namespace interface

    using MacKey = std::shared_ptr< interface::MacKey >;
  } // namespace crypto
} // namespace token

#endif //__TOKENIZATION_HMAC_KEY_HH__
