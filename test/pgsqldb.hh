#ifndef __PGSQLDB_H_
#define __PGSQLDB_H_

#include "token/api/core/database.hh"
#include <iostream>

class PgSqlDB : public token::api::core::TokenDB {
 public:
  PgSqlDB( std::string uri, size_t cxnCount )
    : TokenDB( uri, cxnCount ) {
    std::cout << "Reinitializing SQLite3 Database\n";

    auto connection = dbPool.getConnection( );
    auto statement  = connection << "select tablename from pg_tables where schemaname='public'";
    auto results    = statement.executeQuery( );

    while ( results.next( ) ) {
      ( connection << fmt::format( "drop table {}", results.get< std::string >( 0 ) ) ).execute( );
    }

    std::cout << "  Creating vaults table";
    ( connection << ( "CREATE TABLE vaults ( "
                      "  format    integer,"
                      "  alias     VARCHAR(255),"
                      "  tablename VARCHAR(255),"
                      "  enckey    VARCHAR(255),"
                      "  mackey    VARCHAR(255),"
                      "  durable   boolean,"
                      "  CONSTRAINT vaults_alias_key PRIMARY KEY ( alias ),"
                      "  CONSTRAINT vaults_name_key UNIQUE ( tablename )"
                      ")" ) )
      .execute( );
    std::cout << " - created\n";

    connection.commit( );
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
                                 "  hmac       BYTEA, "
                                 "  crypt      BYTEA, "
                                 "  mask       VARCHAR( {} ), "
                                 "  expiration DATE, "
                                 "  properties BYTEA, "
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

    if ( stmt.executeUpdate( ) > 0 ) {
      connection.commit( );
      return true;
    }

    return false;
  }
};

#endif // __PGSQLDB_H_
