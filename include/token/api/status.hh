#ifndef __TOKENIZATION_STATUS_HH__
#define __TOKENIZATION_STATUS_HH__

namespace token {
  namespace api {
    /**
     * Operational status & error indicator
     */
    class Status {
     public:
      enum Value {
        OPERATIONAL,       /**< Positive status id                       */
        INOPERATIVE_DB,    /**< Negative status id: database failure     */
        INOPERATIVE_CRYPTO /**< Negative status id: cryptography failure */
      };

      /**
       * @brief Status initialzer
       * @param v status enumeration id
       * @param t result text
       * @param d result description
       */
      constexpr Status( Value v, const char *t, const char *d ) noexcept
        : value_( v )
        , text_( t )
        , desc_( d ) {}

      /**
       * @brief Get the status id
       * @return status id
       */
      constexpr Value value( ) { return value_; }
      /**
       * @brief Get the status description
       * @return status description
       */
      constexpr const char *description( ) { return desc_; };

     private:
      Value       value_; /**< Status id          */
      const char *text_;  /**< Result text        */
      const char *desc_;  /**< Status description */
    };

    /** Operational status result */
    static constexpr Status STATUS_OPERATIONAL = {
      Status::Value::OPERATIONAL, "OPERATIONAL", "Operational" };
    /** Database inoperative result */
    static constexpr Status STATUS_INOPERATIVE_DB = {
      Status::Value::INOPERATIVE_DB, "INOPERATIVE", "Inoperative: database failure" };
    /** HSM/Crypto inoperative result */
    static constexpr Status STATUS_INOPERATIVE_CRYPTO = {
      Status::Value::INOPERATIVE_CRYPTO, "INOPERATIVE", "Inoperative: encryption failure" };

  } // namespace api
} // namespace token

#endif //__TOKENIZATION_STATUS_HH__
