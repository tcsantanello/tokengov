
#ifndef __TOKENIZATION_TOKEN_ENTRY_HH__
#define __TOKENIZATION_TOKEN_ENTRY_HH__

#include "token/crypto.hh"
#include <dbc++/dbcpp.hh>
#include <map>
#include <string>

namespace token {
  namespace api {
    using bytea = crypto::bytea;

    /**
     * Token Vault Entry (Token Details)
     */
    struct TokenEntry final {
      std::string                          encKey;     /**< Encryption key name      */
      std::string                          token;      /**< Token                    */
      bytea                                hmac;       /**< HMAC (lookup hash)       */
      bytea                                crypt;      /**< Encrypted data           */
      std::string                          mask;       /**< Raw value masked         */
      std::string                          value;      /**< Raw value                */
      dbcpp::DBTime                        expiration; /**< Expiration date          */
      std::map< std::string, std::string > properties; /**< Miscellaneous properties */

      /**
       * @brief Convert a byte array of serialized name/value pairs into a properties map
       * @param bytes byte array
       * @return properties map
       */
      static std::map< std::string, std::string > deserialize( const bytea &bytes );

      /**
       * @brief Convert a collection of name/value properties into a serialized byte array
       * @param map properties map
       * @return byte array
       */
      static bytea serialize( const std::map< std::string, std::string > &map );

      /**
       * @brief Load the token entry from the selected results
       * @param results result set
       */
      void load( dbcpp::ResultSet &results ) {
        encKey     = results.get< std::string >( "ENCKEY" );
        token      = results.get< std::string >( "TOKEN" );
        hmac       = results.get< bytea >( "HMAC" );
        crypt      = results.get< bytea >( "CRYPT" );
        mask       = results.get< std::string >( "MASK" );
        expiration = results.get< dbcpp::DBTime >( "EXPIRATION" );
        properties = deserialize( results.get< bytea >( "PROPERTIES" ) );
      }

      /**
       * @brief Loading constructor, fill the structure from a table record
       * @param results result set
       */
      explicit TokenEntry( dbcpp::ResultSet &results ) { load( results ); }
      TokenEntry( ) = default;
    };
  } // namespace api
} // namespace token

#endif //__TOKENIZATION_TOKEN_ENTRY_HH__
