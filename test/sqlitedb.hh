#ifndef __SQLITEDB_H_
#define __SQLITEDB_H_

#include "token/api/core/database.hh"
#include <iostream>

class SQLiteDB : public token::api::core::TokenDB {
 public:
  SQLiteDB( std::string uri, size_t cxnCount )
    : TokenDB( uri, cxnCount ) {
    std::cout << "Reinitializing SQLite3 Database\n";

    auto connection = dbPool.getConnection( );
    auto statement  = connection << "select name from sqlite_master where type='table'";
    auto results    = statement.executeQuery( );

    while ( results.next( ) ) {
      ( connection << fmt::format( "drop table {}", results.get< std::string >( 0 ) ) ).execute( );
    }

    std::cout << "  Creating vaults table";
    ( connection << ( "CREATE TABLE vaults ( "
                      "  format    INTEGER,"
                      "  alias     VARCHAR(255),"
                      "  tablename VARCHAR(255),"
                      "  enckey    VARCHAR(255),"
                      "  mackey    VARCHAR(255),"
                      "  durable   INTEGER,"
                      "  CONSTRAINT vaults_alias_key PRIMARY KEY ( alias ),"
                      "  CONSTRAINT vaults_name_key UNIQUE ( tablename )"
                      ")" ) )
      .execute( );
    std::cout << " - created\n";
  }

  virtual bool createVault( const token::api::core::VaultInfo &vault ) override {
    auto        connection = dbPool.getConnection( );
    std::string constraints;

    std::cout << "  Creating token vault " << vault.alias << ": ";

    if ( vault.durable ) {
      constraints = fmt::format(
        "CONSTRAINT {}_pkey PRIMARY KEY ( token ),"
        "CONSTRAINT {}_hmac_key UNIQUE ( hmac )",
        vault.table,
        vault.table );
    } else {
      constraints = fmt::format( "CONSTRAINT {}_tran_tok_key UNIQUE ( token )", vault.table );
    }

    std::cout << " table";
    ( connection << fmt::format( "CREATE TABLE {} ("
                                 "  token      VARCHAR( {} ) NOT NULL,"
                                 "  hmac       BLOB, "
                                 "  crypt      BLOB, "
                                 "  mask       VARCHAR( {} ), "
                                 "  expiration VARCHAR( 20 ), "
                                 "  properties BLOB, "
                                 "  enckey     VARCHAR( 255 ), "
                                 "  {} )",
                                 vault.table,
                                 vault.length,
                                 vault.length,
                                 constraints ) )
      .execute( );

    std::cout << " entry\n";

    auto stmt =
      connection
      << "INSERT INTO vaults ( format, alias, tablename, enckey, mackey, durable ) VALUES ( ?, ?, ?, ?, ?, ? )";

    stmt << vault.format;
    stmt << vault.alias;
    stmt << vault.table;
    stmt << vault.encKeyName;
    stmt << vault.macKeyName;
    stmt << vault.durable;

    std::cout << "Creation complete\n";

    return stmt.executeUpdate( ) > 0;
  }
};

#endif // __SQLITEDB_H_
