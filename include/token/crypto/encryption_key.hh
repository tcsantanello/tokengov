
#ifndef __TOKENIZATION_ENCRYPTION_KEY_HH__
#define __TOKENIZATION_ENCRYPTION_KEY_HH__

#include "token/crypto/base.hh"
#include "base.hh"
#include <memory>
#include <string>

namespace token {
  namespace crypto {
    namespace interface {
      /** Encryption key interface */
      struct EncKey {

        /**
         * @brief Encrypt a string
         * @param data string to encrypt
         * @return encrypted byte array
         */
        bytea encrypt( const std::string &data ) const {
          bytea bytes{data.begin( ), data.end( )};
          return encrypt( bytes );
        }

        /**
         * @brief Decrypt a string
         * @param data encrypted string
         * @return decrypted byte array
         */
        bytea decrypt( const std::string &data ) const {
          bytea bytes{data.begin( ), data.end( )};
          return decrypt( bytes );
        }

        /**
         * @brief Encrypt a sequence of bytes
         * @param data bytes to encrypt
         * @return encrypted byte sequence
         */
        virtual bytea encrypt( const bytea data ) const = 0;

        /**
         * @brief Decrypt a sequence of bytes
         * @param data bytes to decrypt
         * @return decrypted byte sequence
         */
        virtual bytea decrypt( const bytea data ) const = 0;

        /**
         * @brief String representation of the key (e.g. key name)
         * @return string representation
         */
        virtual explicit operator std::string( ) { return ""; };

        /**
         * @brief Identify if the key embeds version specific (key variant) data
         * within the encrypted data
         * @return false
         */
        virtual bool isVersioned( ) const { return false; }
      };
    } // namespace internal

    using EncKey = std::shared_ptr< interface::EncKey >;
  } // namespace crypto
} // namespace token

#endif //__TOKENIZATION_ENCRYPTION_KEY_HH__
