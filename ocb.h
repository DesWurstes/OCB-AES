#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  IV, can be a counter, don't use the
 * same nonce for a key with different message/associated data.
 * @param nonce_length           A trivial parameter about nonce
 * length in bytes. 12 is the recommended value.
 * @param message                Data to be encrypted.
 * @param message_length         Data length in bytes.
 * @param associated_data        See the README.md for this.
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with length [message_length + 16 bytes]
 */
void ocb_encrypt(const unsigned char key[32], const unsigned char nonce[15], unsigned int nonce_length,
  const unsigned char *message, unsigned int message_length, const unsigned char *associated_data,
  int associated_data_length, unsigned char *out);

/**
 * Decrypts a message with associated data.
 * @param key                    256 bit encryption key.
 * @param nonce                  The IV used with the encryption function
 * @param nonce_length           A trivial parameter about nonce
 * length in bytes. 12 is the recommended value.
 * @param encrypted              Encrypted data (aka ciphertext), with
 * the 16-byte authentication tag appended to it.
 * @param encrypted_length       Ciphertext length in bytes, excluding
 * the 16-byte authentication tag.
 * @param associated_data        See the README.md for this.
 * @param associated_data_length Associated Data length in bytes.
 * @param out                    output with length [encrypted_length]
 * @return                       MUST BE CHECKED. Zero if decipher succesful.
 */
int ocb_decrypt(const unsigned char key[32], const unsigned char nonce[15], unsigned int nonce_length,
  const unsigned char *encrypted, unsigned int encrypted_length, const unsigned char *associated_data,
  int associated_data_length, unsigned char *out);

#ifdef __cplusplus
}
#endif
