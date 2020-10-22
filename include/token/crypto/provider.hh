
#ifndef __TOKENIZATION_PROVIDER_HH__
#define __TOKENIZATION_PROVIDER_HH__

#include "token/crypto/base.hh"
#include "token/crypto/encryption_key.hh"
#include "token/crypto/hmac_key.hh"
#include <boost/program_options.hpp>
#include <map>
#include <memory>
#include <string>

namespace token {
  namespace crypto {
    /** Encryption provider interface */
    struct Provider {

      /**
       * @brief Get the encryption key
       * @param name encryption key name
       * @return encryption key
       */
      virtual EncKey getEncKey( std::string name ) = 0;

      /**
       * @brief Get the hashing key
       * @param name hashing key name
       * @return hash key
       */
      virtual MacKey getMacKey( std::string name ) = 0;

      /**
       * @brief Create and get an encryption key
       * @param name key name
       * @param parameters encryption key parameters
       * @return encryption key
       */
      virtual EncKey createEncKey( std::string name, std::map< std::string, std::string > parameters ) {
        return nullptr;
      }

      /**
       * @brief Create and get a hash key
       * @param name key name
       * @param parameters hash key parameters
       * @return hash key
       */
      virtual MacKey createMacKey( std::string name, std::map< std::string, std::string > parameters ) {
        return nullptr;
      }

      /**
       * @brief Fill the variable with random bytes
       * @param v variable
       */
      template < typename T >
      void random( T *v ) {
        random( v, sizeof( *v ) );
      }

      /**
       * @brief Fill the block up to length with random bytes
       * @param block memory block to fill
       * @param length number of bytes to fill
       */
      virtual void random( void *block, size_t length ) = 0;

      /**
       * @brief Set the command line options
       * @param encOptions encryption options
       * @param macOptions hmac options
       */
      virtual void cmdArgs( boost::program_options::options_description &encOptions,
                            boost::program_options::options_description &macOptions ) {}

      /**
       * @brief String representation of the provider
       * @return string representation
       */
      virtual operator std::string( ) { return ""; };
    };
  } // namespace crypto
} // namespace token

#endif //__TOKENIZATION_PROVIDER_HH__
