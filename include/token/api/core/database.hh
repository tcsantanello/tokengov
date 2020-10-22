
#ifndef __TOKENIZATION_DATABASE_HH__
#define __TOKENIZATION_DATABASE_HH__

#include "token/api/core/vaultinfo.hh"
#include "token/api/token_entry.hh"
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <dbc++/dbcpp.hh>
#include <memory>
#include <string>
#include <uri/uri.hh>

namespace token {
  namespace api {
    namespace core {
      using bytea = crypto::bytea;
      using recrypt_type =
        std::function< bytea( const std::string &, const std::string &, const bytea & ) >;

      /**
       * Token Vault Storage Engine
       */
      class TokenDB {

        /**
         * @brief SharedVault cache entry removal callback method.
         *
         * Will remove the cache entry when the shared_ptr is destroyed
         * @param entryPtr vault entry's weak_ptr reference
         * @param name vault's name
         */
        void cleanupCacheEntry( const WeakVault &entryPtr, const std::string &name ) {
          std::lock_guard< std::mutex > guard( vaultLock );
          auto                          weak = vaults[ name ];
          if ( !entryPtr.owner_before( weak ) && !weak.owner_before( entryPtr ) ) {
            vaults.erase( name );
          }
        }

       public:
        /**
         * @brief Create a token database layer
         * @param uri parsed uri object
         * @param cnxCount number of connections
         */
        TokenDB( Uri *uri, size_t cxnCount )
          : TokenDB( uri->toString( ), cxnCount ) {}

        /**
         * @brief Create a token database layer
         * @param uri stringified uri
         * @param cnxCount number of connections
         */
        TokenDB( std::string uri, size_t cxnCount )
          : dbPool( std::move( uri ), cxnCount ) {
          dbPool.setAutoCommit( false );
        }

        /* -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*-
         * Note: The following methods are intended for internal use only; do not call
         * these methods directly
         * -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*/

        /**
         * @brief Get the vault details
         * @param name vault name
         * @return cached vault entry
         */
        SharedVault getVault( const std::string &name ) noexcept( false ) {
          std::lock_guard< std::mutex > guard( vaultLock );
          SharedVault                   vault;

          if ( !( vault = vaults[ name ].lock( ) ) ) {
            auto connection = dbPool.getConnection( );
            auto statement  = connection << "SELECT * FROM vaults WHERE ? IN ( alias, tablename )"
                                        << name;
            auto rs = statement.executeQuery( );

            if ( rs.next( ) ) {
              WeakVault weakPtr = vault;
              auto      cleanup = std::bind( &TokenDB::cleanupCacheEntry, this, weakPtr, name );
              vault             = std::make_shared< VaultInfo >( rs, cleanup );
              vaults[ name ]    = weakPtr;
            } else {
              throw exceptions::TokenNoVaultError( "'" + name + "': vault not defined" );
            }
          }

          return vault;
        }

        /**
         * @brief Vault creation
         * @param vault creation information
         * @return true on success, false on failure
         */
        virtual bool createVault( const VaultInfo &vault ) { return false; }

        /**
         * @brief Get a token entry
         * @param tableName token vault table name
         * @param token token value
         * @return token entry
         */
        virtual TokenEntry get( const std::string &tableName, const std::string &token );

        /**
         * @brief Get a token entry by the HMAC (hashed value)
         * @param tableName token vault table name
         * @param hmac hashed value
         * @return token entry
         */
        virtual std::vector< TokenEntry > get( const std::string &tableName, const bytea &hmac );

        /**
         * @brief Insert a new token entry
         * @param tableName token vault table name
         * @param entry token entry
         */
        virtual void insert( const std::string &tableName, const TokenEntry &entry );

        /**
         * @brief Remove a token entry
         * @param tableName token vault table name
         * @param entry token entry
         */
        virtual void remove( const std::string &tableName, TokenEntry &entry );

        /**
         * @brief Update a token entry
         * @param tableName token vault table name
         * @param entry token entry
         */
        virtual void update( const std::string &tableName, TokenEntry &entry );

        /**
         * @brief Remove a token
         * @param tableName token vault table name
         * @param token token
         */
        TokenEntry remove( const std::string &tableName, const std::string &token ) {
          TokenEntry entry{ };

          entry.token = token;

          remove( tableName, entry );

          return entry;
        }

        /**
         * @brief Remove a token by the HMAC (hashed value)
         * @param tableName token vault table name
         * @param hmac hashed value
         */
        TokenEntry remove( const std::string &tableName, const bytea &hmac ) {
          TokenEntry entry{ };

          entry.hmac = hmac;

          remove( tableName, entry );

          return entry;
        }

        /**
         * @brief Perform a search on a vault, returning records that match the search criteria
         * @note All values within the same search field group are or'ed together, and and'd with
         * those from other groups
         * @param tableName table name of the vault
         * @param tokens collection of tokens to find
         * @param hmacs collection of hashed values to find
         * @param expirations collection of expiration dates to find
         * @param sortField field to sort on (default: creation_date)
         * @param sortAsc sort ascending (true), or sort descending (false)
         * @param offset starting point for the record search (capture offset)
         * @param limit maximum number of records to retrieve
         * @param recordCount output field representing the overall count of records matching the
         * criteria
         * @return collection of token entries matching the criteria
         */
        virtual std::vector< TokenEntry > query( const std::string &                 tableName,
                                                 const std::vector< std::string > &  tokens,
                                                 const std::vector< bytea > &        hmacs,
                                                 const std::vector< dbcpp::DBTime > &expirations,
                                                 std::string                         sortField,
                                                 bool                                sortAsc,
                                                 size_t                              offset,
                                                 size_t                              limit,
                                                 size_t *                            recordCount );

        /**
         * @brief Update the encryption key associated with a vault
         * @note This operation does not re-key existing entries
         * @param vault token vault info
         * @param encKey new encryption key
         * @return true on success, false on failure
         */
        virtual bool updateKey( SharedVault vault, const std::string &encKey );

        /**
         * @brief Update the encryption key associated with a vault
         * @note This operation does not re-key existing entries
         * @param vault alias or table name of the vault
         * @param encKey new encryption key
         * @return true on success, false on failure
         */
        virtual bool updateKey( const std::string &vault, const std::string &encKey );

        /**
         * @brief Update the vault encryption key, and re-encrypt existing entries
         * @param vault token vault info
         * @param encKey new encryption key
         * @param recrypt re-encryption method
         * @return true on success, false on failure
         */
        virtual bool rekey( SharedVault vault, const std::string &encKey, recrypt_type recrypt );

        /**
         * Test the database connection
         * @return true on success, false on failure
         */
        bool test( ) {
          try {
            return dbPool.getConnection( ).test( );
          } catch ( ... ) {
            return false;
          }
        }

       protected:
        std::map< std::string, WeakVault > vaults;    /**< Vault info cache */
        std::mutex                         vaultLock; /**< Vault cache lock */
        dbcpp::Pool                        dbPool;    /**< Database pool    */
      };

    } // namespace core
  }   // namespace api
} // namespace token

#endif //__TOKENIZATION_DATABASE_HH__
