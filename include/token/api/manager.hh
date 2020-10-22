
#ifndef __TOKENIZATION_MANAGER_HH__
#define __TOKENIZATION_MANAGER_HH__

#include "token/api/core/database.hh"
#include "token/api/status.hh"
#include "token/api/token_entry.hh"
#include "token/crypto.hh"
#include <functional>
#include <memory>

namespace token {
  namespace api {

    /**
     * Token manager, provides methods of interfacing with the token vault by way of the cryptographic
     * provider (token::crypto::Provider) and the token database storage (token::TokenDB).
     */
    class TokenManager {
     public:
      using RandBytes = std::function< void( void *data, size_t length ) >;
      using Generator = std::function< std::string( RandBytes, std::string, std::string * ) >;

      /**
       * @brief Construct token manager instance
       * @param _provider shared encryption provider
       * @param _storage shared token storage
       */
      TokenManager( std::shared_ptr< crypto::Provider > _provider, std::shared_ptr< core::TokenDB > _storage )
        : provider( std::move( _provider ) )
        , storage( std::move( _storage ) ) {}

      /**
       * @brief Generate a token for the specified value
       * @param vault token vault to store the entry
       * @param value raw value to tokenize
       * @param data TokenEntry structure containing additional data
       * @return token entry representing the stored data
       */
      TokenEntry tokenize( const std::string &vault, const std::string &value, TokenEntry *data );

      /**
       * @brief Get the stored values for the specified token
       * @param vault token vault in which the token resides
       * @param token tokenized value
       * @return token entry representing the stored data
       */
      TokenEntry detokenize( const std::string &vault, const std::string &token );

      /**
       * @brief Get the stored values for the specified value
       * @param vault token vault in which the value resides
       * @param value raw value
       * @return token entry representing the stored data
       */
      std::vector< TokenEntry > retrieve( const std::string &vault, const std::string &value );

      /**
       * @brief Remove a token (and values) from the specified vault
       * @param vault token vault in which the token resides
       * @param token tokenized value
       * @return token entry that was removed from the data store
       */
      TokenEntry remove( const std::string &vault, const std::string &token );

      /**
       * @brief Update the values associated with the token entry (token value)
       * @param vault token vault in which the token resides
       * @param entry token values
       * @return token entry that was removed from the data store
       */
      TokenEntry update( const std::string &vault, TokenEntry &entry );

      /**
       * @brief Perform a search on a vault, returning records that match the search criteria
       * @note All values within the same search field group are or'ed together, and and'd with those
       *       from other groups
       * @param vault name of the vault
       * @param tokens collection of tokens to find
       * @param values collection of raw values to find
       * @param expirations collection of expiration dates to find
       * @param offset starting point for the record search (capture offset)
       * @param limit maximum number of records to retrieve
       * @param recordCount output field representing the overall count of records matching the
       * criteria
       * @return collection of token entries matching the criteria
       */
      std::vector< TokenEntry > query( const std::string &                 vault,
                                       const std::vector< std::string > &  tokens,
                                       const std::vector< std::string > &  values,
                                       const std::vector< dbcpp::DBTime > &expirations,
                                       const std::string &                 sortField,
                                       bool                                sortAsc,
                                       size_t                              offset,
                                       size_t                              limit,
                                       size_t *                            recordCount );

      /**
       * Get the general operational status of the service
       * @return operational status
       */
      Status status( );

      /**
       * Get the general operational status of the service
       * @return operational status
       */
      Status status( const std::string &vault );

      /**
       * @brief Create a new vault
       * @param alias vault name
       * @param encKey encryption key name
       * @param macKey hash key name
       * @param format token format
       * @param value_len length of the value
       * @param durable vault is durable
       * @param tableName name of the table (empty: construct from alias, len, format and durability flag)
       */
      bool createVault( const std::string &alias,
                        const std::string &encKey,
                        const std::string &macKey,
                        size_t             format,
                        size_t             value_len,
                        bool               durable,
                        const std::string &tableName = "" );

      /**
       * @brief Re-encrypt a vault under a new key
       * @param vault name or alias of a vault
       * @param encKey encryption key name
       * @param deep true [default] for full re-encryption, false to update encryption key for new rows
       */
      bool rekeyVault( const std::string &vault, const std::string &encKey, bool deep = true );

      /**
       * @brief Add a new generator
       * @param id generator/format id
       * @param generator token generator
       * @return true on success, false on failure
       */
      static bool generatorRegister( size_t id, Generator generator ) {
        boost::lock_guard< boost::shared_mutex > guard( generatorLock );

        if ( generators.find( id ) == generators.end( ) ) {
          generators[ id ] = std::move( generator );
          return true;
        }

        return false;
      }

      /**
       * @brief Generate random bytes
       * @param block region to fill with random bytes
       * @param length number of bytes to fill
       */
      void random( void *block, size_t length ) { provider->random( block, length ); }

     public:
      enum Format {
        /**
         * @brief Tokenization format replace with completely random characters
         */
        RANDOM_FORMAT,
        /**
         * @brief Tokenization format replace all characters with the
         * types (alpha,numeric,punctuation) found in the string
         */
        FP_RANDOM_FORMAT,
        /**
         * @brief Tokenization format that produces an invalid date
         * (numerically speaking) but in the structure of the input
         * value (i.e. DD Month YYYY -> NN Abslkf NNNN, MM/DD/YYYY -> NN/NN/NNNN)
         */
        DATE_FORMAT,
        /**
         * @brief Tokenization format that preserves the structure of
         * an email address (xxx@xxx.xxx), but produces an otherwise
         * random string.
         */
        EMAIL_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * passing a LUHN check where the last 4 are the same as
         * the original value
         */
        L4_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * passing a LUHN check where the first 6 are the same as
         * the original value
         */
        F6_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * passing a LUHN check where the first 2 and last 4 are
         * the same as the original value.
         */
        F2L4_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * passing a LUHN check where the first 6 and last 4 are
         * the same as the original value.
         */
        F6L4_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * failing a LUHN check where the last 4 are the same as
         * the original value
         */
        L4_NOLUHN_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * failing a LUHN check where the first 6 are the same as
         * the original value
         */
        F6_NOLUHN_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * failing a LUHN check where the first 2 and last 4 are
         * the same as the original value.
         */
        F2L4_NOLUHN_FORMAT,
        /**
         * @brief Tokenization format of a randomized card number
         * failing a LUHN check where the first 6 and last 4 are
         * the same as the original value.
         */
        F6L4_NOLUHN_FORMAT,
      };

     protected:
      /**
       * @brief Generate a token for the supplied value
       * @param vault vault information
       * @param value value to tokenize
       * @param mask masked value
       * @return generated token
       * @throws InvalidTokenFormat if the format specified does not have a generator
       */
      std::string generate( core::SharedVault vault, const std::string &value, std::string *mask );

      /**
       * @brief Get the vault information, and keys
       * @param name vault name
       * @return vault info
       */
      core::SharedVault getVaultInfo( const std::string &name ) {
        auto vault = storage->getVault( name );
        vault->loadKeys( provider.get( ) );
        return vault;
      }

     private:
      using GeneratorMap = std::map< size_t, Generator >;

      /** RWLock for the token generators */
      static boost::shared_mutex generatorLock;
      /** Token generators */
      static GeneratorMap generators;
      /** Cryptography provider */
      std::shared_ptr< crypto::Provider > provider;
      /** Storage provider */
      std::shared_ptr< core::TokenDB > storage;
    };
  } // namespace api
} // namespace token

#endif //__TOKENIZATION_MANAGER_HH__
