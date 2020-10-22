
#include "token/api.hh"
#include <boost/thread/shared_lock_guard.hpp>
#include <functional>
#include <spdlog/spdlog.h>

#include <spdlog/sinks/null_sink.h>

#define LOG( lvl, fmt, ... )                                                                                           \
  do {                                                                                                                 \
    if ( logger->should_log( spdlog::level::lvl ) ) {                                                                  \
      logger->lvl( fmt, ##__VA_ARGS__ );                                                                               \
    }                                                                                                                  \
  } while ( 0 )

namespace token {
  namespace api {
    /** Manager logger */
    std::shared_ptr< spdlog::logger > logger = token::api::create_logger( "token::api::manager", { } );
    boost::shared_mutex               TokenManager::generatorLock;

    TokenEntry TokenManager::tokenize( const std::string &vault, const std::string &value, TokenEntry *data ) {
      static const size_t MAX_RETRIES = 10;

      auto rc        = TokenEntry( );
      auto vaultInfo = getVaultInfo( vault );

      LOG( info,
           "Preparing to tokenize value for {} a {} vault",
           vault,
           vaultInfo->durable ? "durable" : "transactional" );

      if ( vaultInfo->durable ) {
        LOG( info, "Retrieving existing token from vault {}", vault );

        auto entries = retrieve( vault, value );

        if ( !entries.empty( ) ) {
          rc = entries[ 0 ];

          goto finish;
        }
      }

      if ( data != nullptr ) {
        if ( !data->token.empty( ) ) {
          LOG( debug, "Using supplied token {} for vault {}", vault, data->token );

          rc.token = data->token;
        }

        rc.expiration = data->expiration;
        rc.properties = data->properties;
      }

      if ( rc.token.empty( ) ) {
        LOG( trace, "Generating token for vault {}", vault );

        rc.token = generate( vaultInfo, value, &rc.mask );

        LOG( trace, "Generated token {} for vault {}", rc.token, vault );
      }

      rc.value = value;

      LOG( trace, "Hashing value for token {} from vault {}", rc.token, vault );
      rc.hmac = vaultInfo->macKey->hash( value );

      LOG( trace, "Encrypting value for token {} from vault {}", rc.token, vault );
      rc.crypt = vaultInfo->encKey->encrypt( value );

      if ( !vaultInfo->encKey->isVersioned( ) ) {
        LOG( trace, "Saving unversioned key for {} from {}", rc.token, vault );

        rc.encKey = vaultInfo->encKeyName;
      }

      for ( size_t num = 0;; ++num ) {
        try {
          storage->insert( vaultInfo->table, rc );

          break;
        } catch ( dbcpp::DBException &ex ) {
          LOG( warn, "Failed to insert token {} into vault {}: {}", rc.token, vault, ex.what( ) );

          bool        is_token_dup = false;
          std::string err          = ex.what( );

          std::transform( err.begin( ), err.end( ), err.begin( ), ::toupper );

          is_token_dup = ( ( err.find( "UNIQUE" ) != std::string::npos ) && //
                           ( err.find( "TOKEN" ) != std::string::npos ) );

          if ( !is_token_dup ) {
            LOG( debug,
                 "Exception on {} for {} did not identify if it is a duplicate entry, performing lookup",
                 vault,
                 rc.token );

            is_token_dup = !storage->get( vaultInfo->table, rc.token ).token.empty( );
          }

          if ( !is_token_dup ) {
            LOG( debug, "{} is not a duplicate for vault {}", rc.token, vault );
            throw ex;
          }

          if ( num >= ( MAX_RETRIES - 1 ) ) {
            LOG( warn, "Maximum retries for tokenize operation failed against vault {}", vault );
            throw ex;
          }

          LOG( info, "Regenerating token for vault {}", vault );

          rc.token = generate( vaultInfo, value, nullptr );
        }
      }

    finish:
      LOG( info, "Successfully tokenized value for vault {}: {}", vault, rc.token );

      return rc;
    }

    TokenEntry TokenManager::detokenize( const std::string &vault, const std::string &token ) {
      LOG( info, "Detokenizing value for vault {} token {}", vault, token );
      LOG( trace, "Getting vault info for {}", vault );

      auto vaultInfo = getVaultInfo( vault );
      auto entry     = storage->get( vaultInfo->table, token );
      auto key       = vaultInfo->encKey;

      if ( !entry.encKey.empty( ) ) {
        LOG( trace, "Getting encryption key for vault {} token {}", vault, token );
        key = provider->getEncKey( entry.encKey );
      }

      if ( !entry.crypt.empty( ) ) {
        LOG( trace, "Decrypting value for vault {} token {}", vault, token );

        auto dec    = key->decrypt( entry.crypt );
        entry.value = std::string( dec.begin( ), dec.end( ) );
      }

      LOG( info, "Successfully retrieved value for vault {} token {}", vault, token );

      return entry;
    }

    std::vector< TokenEntry > TokenManager::retrieve( const std::string &vault, const std::string &value ) {
      std::map< std::string, crypto::EncKey > keys;
      LOG( info, "Performing token lookup by value for vault {}", vault );
      LOG( trace, "Getting vault info for {}", vault );
      auto vaultInfo = getVaultInfo( vault );

      LOG( trace, "Hashing value for lookup in vault {}", vault );
      auto bytes   = vaultInfo->macKey->hash( value );
      auto entries = storage->get( vaultInfo->table, bytes );

      for ( auto &entry : entries ) {
        if ( !entry.crypt.empty( ) ) {
          auto key = vaultInfo->encKey;

          if ( !entry.encKey.empty( ) ) {
            if ( !( key = keys[ entry.encKey ] ) ) {
              LOG( trace, "Getting encryption key for vault {} token {}", vault, entry.token );

              key                  = provider->getEncKey( entry.encKey );
              keys[ entry.encKey ] = key;
            }
          }

          LOG( trace, "Decrypting value for vault {} token {}", vault, entry.token );
          auto dec    = key->decrypt( entry.crypt );
          entry.value = std::string( dec.begin( ), dec.end( ) );
        }
      }

      LOG( info, "Successfully retrieved {} values from vault {}", entries.size( ), vault );

      return entries;
    }

    TokenEntry TokenManager::remove( const std::string &vault, const std::string &token ) {
      LOG( info, "Removing token {} from vault {}", token, vault );
      LOG( trace, "Getting vault info for {}", vault );
      auto vaultInfo = getVaultInfo( vault );

      LOG( trace, "Removing token {} from vault {}", token, vault );
      auto entry = storage->remove( vaultInfo->table, token );
      auto key   = vaultInfo->encKey;

      if ( !entry.encKey.empty( ) ) {
        LOG( trace, "Getting encryption key for vault {} token {}", vault, entry.token );

        key = provider->getEncKey( entry.encKey );
      }

      if ( !entry.crypt.empty( ) ) {
        LOG( trace, "Decrypting value for vault {} token {}", vault, entry.token );

        auto dec    = key->decrypt( entry.crypt );
        entry.value = std::string( dec.begin( ), dec.end( ) );
      }

      LOG( info, "Successfully removed {} from vault {}", token, vault );

      return entry;
    }

    TokenEntry TokenManager::update( const std::string &vault, TokenEntry &entry ) {
      LOG( info, "Updating token {} from vault {}", entry.token, vault );
      auto rc = TokenEntry( );
      LOG( trace, "Getting vault info for {}", vault );
      auto vaultInfo = getVaultInfo( vault );

      rc.token      = entry.token;
      rc.expiration = entry.expiration;
      rc.properties = entry.properties;

      if ( !entry.value.empty( ) ) {
        LOG( trace, "Setting new value for vault {} token {}", vault, entry.token );

        if ( !vaultInfo->encKey->isVersioned( ) ) {
          LOG( trace, "Saving unversioned key for {} from {}", rc.token, vault );

          rc.encKey = vaultInfo->encKeyName;
        }

        LOG( trace, "Hashing value for token {} from vault {}", rc.token, vault );
        rc.hmac = vaultInfo->macKey->hash( entry.value );

        LOG( trace, "Encrypting value for token {} from vault {}", rc.token, vault );
        rc.crypt = vaultInfo->encKey->encrypt( entry.value );
        rc.value = entry.value;
      }

      try {
        storage->update( vaultInfo->table, rc );
      } catch ( std::exception &ex ) {
        LOG( debug, "{}", ex.what( ) );
        throw ex;
      }

      if ( ( !rc.crypt.empty( ) ) && ( entry.value.empty( ) ) ) {
        LOG( trace, "Decrypting value for vault {} token {}", vault, entry.token );

        auto dec    = vaultInfo->encKey->decrypt( entry.crypt );
        entry.value = std::string( dec.begin( ), dec.end( ) );
      }

      LOG( info, "Successfully updated {} from vault {}", entry.token, vault );

      return rc;
    }

    std::vector< TokenEntry > TokenManager::query( const std::string &                 vault,
                                                   const std::vector< std::string > &  tokens,
                                                   const std::vector< std::string > &  values,
                                                   const std::vector< dbcpp::DBTime > &expirations,
                                                   const std::string &                 sortField,
                                                   bool                                sortAsc,
                                                   size_t                              offset,
                                                   size_t                              limit,
                                                   size_t *                            recordCount ) {
      LOG( info, "Performing query against vault {}", vault );
      std::vector< bytea >      hmacs;
      std::vector< TokenEntry > rc;
      auto                      vaultInfo = getVaultInfo( vault );

      std::transform( values.begin( ), values.end( ), std::back_inserter( hmacs ), [ & ]( const std::string &value ) {
        return vaultInfo->macKey->hash( value );
      } );

      rc =
        storage->query( vaultInfo->table, tokens, hmacs, expirations, sortField, sortAsc, offset, limit, recordCount );

      for ( auto &entry : rc ) {
        if ( !entry.crypt.empty( ) ) {
          auto key = vaultInfo->encKey;

          if ( !entry.encKey.empty( ) ) {
            key = provider->getEncKey( entry.encKey );
          }

          LOG( trace, "Decrypting entry for token {} from vault {}", entry.token, vault );

          auto dec    = key->decrypt( entry.crypt );
          entry.value = std::string( dec.begin( ), dec.end( ) );
        }
      }

      LOG( info, "Successfully found {} entries from querying vault {}", rc.size( ), vault );

      return rc;
    }

    std::string TokenManager::generate( core::SharedVault vault, const std::string &value, std::string *mask ) {
      Generator generator = nullptr;
      auto      rand      = [ this ]( void *block, size_t length ) -> void { random( block, length ); };

      LOG( info, "Generating token against vault {} (format: {})", vault->alias, vault->format );

      LOG( debug, "Looking up token generator format id {}", vault->format );

      {
        auto guard    = boost::shared_lock< boost::shared_mutex >( generatorLock );
        auto iterator = generators.find( vault->format );

        if ( iterator == generators.end( ) ) {
          LOG( critical, "Failed to find generator format {} for vault {}", vault->alias, vault->format );

          throw exceptions::InvalidTokenFormat( vault->alias, vault->format );
        }

        generator = iterator->second;
      }

      auto token = generator( rand, value, mask );

      LOG( info, "Successfully generated token {} for vault {}", token, vault->alias );

      return token;
    }

    Status TokenManager::status( ) {
      LOG( info, "Performing generic status using provider random" );

      try {
        uint8_t r = { };
        provider->random( &r, sizeof( r ) );
      } catch ( std::exception &e ) {
        LOG( critical, "Generic status check failed: crypto" );

        return STATUS_INOPERATIVE_CRYPTO;
      }

      try {
        LOG( info, "Performing generic status using database test" );
        if ( storage->test( ) ) {
          LOG( info, "Generic status check passed" );
          return STATUS_OPERATIONAL;
        }
      } catch ( std::exception &e ) {
      }

      LOG( critical, "Generic status check failed: database" );
      return STATUS_INOPERATIVE_DB;
    }

    Status TokenManager::status( const std::string &vault ) {
      LOG( info, "Performing status using crypto keys for vault {}", vault );

      auto vaultInfo = getVaultInfo( vault );

      try {
        vaultInfo->encKey->encrypt( vault );
      } catch ( std::exception &e ) {
        LOG( critical, "Status check for vault {} failed: crypto", vault );
        return STATUS_INOPERATIVE_CRYPTO;
      }

      try {
        if ( storage->test( ) ) {
          LOG( info, "Vault {} status check passed", vault );
          return STATUS_OPERATIONAL;
        }
      } catch ( std::exception &e ) {
      }

      LOG( critical, "Status check for vault {} failed: database", vault );

      return STATUS_INOPERATIVE_DB;
    }

    bool TokenManager::createVault( const std::string &alias,
                                    const std::string &encKey,
                                    const std::string &macKey,
                                    size_t             format,
                                    size_t             value_len,
                                    bool               durable,
                                    const std::string &tableName ) {
      static const std::string suffixes[] = { "su", "mu" };
      core::VaultInfo          vault;

      vault.format     = format;
      vault.length     = value_len;
      vault.alias      = std::move( alias );
      vault.encKeyName = std::move( encKey );
      vault.macKeyName = std::move( macKey );
      vault.durable    = durable;

      if ( tableName.empty( ) ) {
        vault.table = fmt::format( "{}{}_{}_{}", alias, value_len, format, suffixes[ durable ] );
      } else {
        vault.table = std::move( tableName );
      }

      return storage->createVault( vault );
    }

    bool TokenManager::rekeyVault( const std::string &vault, const std::string &encKey, bool deep ) {
      auto                                    vaultInfo = storage->getVault( vault );
      std::map< std::string, crypto::EncKey > cache;
      core::recrypt_type                      doer =
        [ & ]( const std::string &destKey, const std::string &srcKey, const bytea &src ) -> bytea {
        bytea          decrypted;
        crypto::EncKey dkey = cache[ destKey ];
        crypto::EncKey skey;

        if ( !( skey = cache[ srcKey ] ) ) {
          if ( !( skey = provider->getEncKey( srcKey ) ) ) {
            LOG( critical, "Unable to acquire encryption key {}", srcKey );
            return decrypted;
          }

          cache[ srcKey ] = skey;
        }

        try {
          decrypted = skey->decrypt( src );
        } catch ( std::exception &ex ) {
          LOG( critical, "Error decrypting value" );
          return decrypted;
        }

        try {
          return dkey->encrypt( decrypted );
        } catch ( std::exception &ex ) {
          LOG( critical, "Error encrypting value" );
        }

        return { };
      };

      auto newKey     = provider->getEncKey( encKey );
      cache[ encKey ] = newKey;

      if ( ( !deep ) || ( !newKey->isVersioned( ) ) ) {
        bool rc = storage->updateKey( vaultInfo, encKey );
        if ( !deep ) {
          return rc;
        }
      }

      return storage->rekey( vaultInfo, encKey, doer );
    }
  } // namespace api
} // namespace token
