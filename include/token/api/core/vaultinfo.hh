
#ifndef __TOKENIZATION_VAULTINFO_HH__
#define __TOKENIZATION_VAULTINFO_HH__

#include "token/api/core/database.hh"
#include "token/crypto.hh"
#include "token/exceptions.hh"
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <dbc++/dbcpp.hh>
#include <functional>

namespace token {
  namespace api {
    namespace core {
      struct VaultInfo final : public std::enable_shared_from_this< VaultInfo > {
        using cleanup_f = std::function< void( ) >;

        cleanup_f             cleanup;    /**< Cleanup handler                 */
        size_t                format;     /**< Vault token format              */
        std::string           alias;      /**< Vault name                      */
        std::string           table;      /**< Vault table name                */
        std::string           encKeyName; /**< Encryption key name             */
        std::string           macKeyName; /**< HMAC key name                   */
        token::crypto::EncKey encKey;     /**< Encryption key                  */
        token::crypto::MacKey macKey;     /**< HMAC key                        */
        bool                  durable;    /**< Vault has durable tokens        */
        size_t                length;     /**< Value length: only for creation */

        /**
         * @brief Load the vault information from a result set
         * @param results result set
         */
        void load( const dbcpp::ResultSet &results ) {
          format     = results.get< size_t >( "FORMAT" );
          alias      = results.get< std::string >( "ALIAS" );
          table      = results.get< std::string >( "TABLENAME" );
          encKeyName = results.get< std::string >( "ENCKEY" );
          macKeyName = results.get< std::string >( "MACKEY" );
          durable    = results.get< bool >( "DURABLE" );
        }

        /**
         * @brief Identify if the encryption keys have been loaded
         * @return true if loaded, false if not
         */
        bool hasKeys( ) { return ( encKey != nullptr ) && ( macKey != nullptr ); }

        /**
         * @brief Load the encryption keys
         * @param provider encryption provider
         * @return current object (this)
         */
        VaultInfo &loadKeys( crypto::Provider *provider ) {
          if ( ( provider != nullptr ) && ( !hasKeys( ) ) ) {
            if ( !( encKey = provider->getEncKey( encKeyName ) ) ) {
              throw exceptions::TokenCryptographyError( "Error acquiring key: " + encKeyName );
            }

            if ( !( macKey = provider->getMacKey( macKeyName ) ) ) {
              throw exceptions::TokenCryptographyError( "Error acquiring key: " + macKeyName );
            }
          }
          return *this;
        }

        VaultInfo( ) = default;

        VaultInfo( VaultInfo &rhs ) = default;

        /**
         * @brief Load values from a db query result set
         * @param results db result set
         * @param _cleanup deconstructor/cleanup method
         */
        explicit VaultInfo( const dbcpp::ResultSet &results, cleanup_f _cleanup )
          : cleanup( std::move( _cleanup ) ) {
          load( results );
        }

        ~VaultInfo( ) {
          if ( cleanup ) {
            cleanup( );
          }
        }
      };

      using WeakVault   = std::weak_ptr< VaultInfo >;
      using SharedVault = std::shared_ptr< VaultInfo >;
    } // namespace core
  }   // namespace api
} // namespace token

#endif //__TOKENIZATION_VAULTINFO_HH__
