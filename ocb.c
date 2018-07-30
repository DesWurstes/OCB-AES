// AES OCB Licenses: http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm
// Applied license: License 1
// Found at: http://web.cs.ucdavis.edu/~rogaway/ocb/license1.pdf
// OCB FAQ: http://www.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm

// The source code is derived from this, except the blockcipher functions:
// https://tools.ietf.org/pdf/rfc7253.pdf

// For the curious:
// Unneeded extra: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
// More extra: https://link.springer.com/content/pdf/10.1007%2F978-3-642-21702-9_18.pdf

// Cipher functions are taken from (Public domain)
// https://github.com/kokke/tiny-AES-c/blob/master/aes.c

#ifdef __GNUC__
#define USE_BUILTIN
#define ntz(a) __builtin_ctz((unsigned int) a)
#define ntz_round(a) \
((a) == 0) ? 0 : (sizeof(unsigned int) * 8 - __builtin_clz((unsigned int) a) - 1)
#endif

static const unsigned char sbox[256] = {
  //0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const unsigned char rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const unsigned char rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void sub_bytes(unsigned char state[16])
{
  for (int i = 0; i < 16; i++)
    state[i] = sbox[state[i]];
}

static void inv_sub_bytes(unsigned char state[16])
{
  for (int i = 0; i < 16; i++)
    state[i] = rsbox[state[i]];
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void shift_rows(unsigned char state[16])
{
  unsigned char temp;

  // Rotate first row 1 columns to left
  temp        = state[0 * 4 + 1];
  state[0 * 4 + 1] = state[1 * 4 + 1];
  state[1 * 4 + 1] = state[2 * 4 + 1];
  state[2 * 4 + 1] = state[3 * 4 + 1];
  state[3 * 4 + 1] = temp;

  // Rotate second row 2 columns to left
  temp        = state[0 * 4 + 2];
  state[0 * 4 + 2] = state[2 * 4 + 2];
  state[2 * 4 + 2] = temp;

  temp        = state[1 * 4 + 2];
  state[1 * 4 + 2] = state[3 * 4 + 2];
  state[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to left
  temp        = state[0 * 4 + 3];
  state[0 * 4 + 3] = state[3 * 4 + 3];
  state[3 * 4 + 3] = state[2 * 4 + 3];
  state[2 * 4 + 3] = state[1 * 4 + 3];
  state[1 * 4 + 3] = temp;
}

static void inv_shift_rows(unsigned char state[16])
{
  unsigned char temp;

  // Rotate first row 1 columns to right
  temp = state[3 * 4 + 1];
  state[3 * 4 + 1] = state[2 * 4 + 1];
  state[2 * 4 + 1] = state[1 * 4 + 1];
  state[1 * 4 + 1] = state[0 * 4 + 1];
  state[0 * 4 + 1] = temp;

  // Rotate second row 2 columns to right
  temp = state[0 * 4 + 2];
  state[0 * 4 + 2] = state[2 * 4 + 2];
  state[2 * 4 + 2] = temp;

  temp = state[1 * 4 + 2];
  state[1 * 4 + 2] = state[3 * 4 + 2];
  state[3 * 4 + 2] = temp;

  // Rotate third row 3 columns to right
  temp = state[0 * 4 + 3];
  state[0 * 4 + 3] = state[1 * 4 + 3];
  state[1 * 4 + 3] = state[2 * 4 + 3];
  state[2 * 4 + 3] = state[3 * 4 + 3];
  state[3 * 4 + 3] = temp;
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void add_round_key(unsigned char round, unsigned char state[16], const unsigned char * __restrict round_key)
{
  for (int i = 0; i < 16; ++i)
    state[i] ^= round_key[(round * 16) + i];
}

static inline unsigned char xtime(unsigned char x)
{
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static inline unsigned char Multiply(unsigned char x, unsigned char y) {
  return (((y & 1) * x) ^
    ((y >> 1 & 1) * xtime(x)) ^
    ((y >> 2 & 1) * xtime(xtime(x))) ^
    ((y >> 3 & 1) * xtime(xtime(xtime(x)))));
}

// MixColumns function mixes the columns of the state matrix
static void mix_columns(unsigned char state[16])
{
  unsigned char Tmp, Tm, t;
  for (int i = 0; i < 4; i++)
  {
    t   = state[4 * i + 0];
    Tmp = state[4 * i + 0] ^ state[4 * i + 1] ^ state[4 * i + 2] ^ state[4 * i + 3];
    Tm  = state[4 * i + 0] ^ state[4 * i + 1] ; Tm = xtime(Tm);  state[4 * i + 0] ^= Tm ^ Tmp;
    Tm  = state[4 * i + 1] ^ state[4 * i + 2] ; Tm = xtime(Tm);  state[4 * i + 1] ^= Tm ^ Tmp;
    Tm  = state[4 * i + 2] ^ state[4 * i + 3] ; Tm = xtime(Tm);  state[4 * i + 2] ^= Tm ^ Tmp;
    Tm  = state[4 * i + 3] ^ t ;           Tm = xtime(Tm);  state[4 * i + 3] ^= Tm ^ Tmp;
  }
}

static void inv_mix_columns(unsigned char state[16])
{
  unsigned char a, b, c, d;
  for (int i = 0; i < 4; i++)
  {
    a = state[4 * i + 0];
    b = state[4 * i + 1];
    c = state[4 * i + 2];
    d = state[4 * i + 3];

    state[4 * i + 0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    state[4 * i + 1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    state[4 * i + 2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    state[4 * i + 3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}

// Cipher is the main function that encrypts the PlainText.
// round_key is of len 240 chars.
static void cipher(unsigned char state[16], const unsigned char * __restrict round_key)
{
  // Add the First round key to the state before starting the rounds.
  add_round_key(0, state, round_key);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (unsigned char round = 1; round < 14; round++)
  {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(round, state, round_key);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  sub_bytes(state);
  shift_rows(state);
  add_round_key(14, state, round_key);
}

static void decipher(unsigned char state[16], const unsigned char * __restrict round_key)
{

  // Add the First round key to the state before starting the rounds.
  add_round_key(14, state, round_key);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (unsigned char round = 13; round > 0; round--)
  {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(round, state, round_key);
    inv_mix_columns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(0, state, round_key);
}

static void key_expansion(unsigned char* __restrict round_key, const unsigned char* __restrict key)
{
  unsigned i, j, k;
  unsigned char tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
#ifdef __GNUC__
    __builtin_memcpy(round_key, key, 32);
#else
    for (int i = 0; i < 32; i++)
      round_key[i] = key[i];
#endif

  // All other round keys are found from the previous round keys.
  for (i = 8; i < 4 * (14 + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0] = round_key[k + 0];
      tempa[1] = round_key[k + 1];
      tempa[2] = round_key[k + 2];
      tempa[3] = round_key[k + 3];
    }

    if (i % 8 == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] = tempa[0] ^ rcon[i/8];
    }
    if (i % 8 == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    j = i * 4; k = (i - 8) * 4;
    round_key[j + 0] = round_key[k + 0];
    round_key[j + 1] = round_key[k + 1];
    round_key[j + 2] = round_key[k + 2];
    round_key[j + 3] = round_key[k + 3];
    round_key[j + 0] ^= tempa[0];
    round_key[j + 1] ^= tempa[1];
    round_key[j + 2] ^= tempa[2];
    round_key[j + 3] ^= tempa[3];
  }
}
// End of AES common bundle


static void double_arr(unsigned char s[16]) {
  const unsigned char first_bit = -(s[0] >> 7);
  for (int i = 0; i < 15; i++) {
    s[i] &= 127; // ~(1 << 7)
    s[i] <<= 1;
    s[i] |= s[i+1] >> 7;
  }
  s[15] &= 127;
  s[15] <<= 1;
  s[15] ^= first_bit & 135;
}

#ifndef USE_BUILTIN
// largest x such that 2^x | a - n for a - n > 0
static inline unsigned int ntz_round(unsigned int a) {
  int k = 0;
  while (a >>= 1)
    k++;
  return (unsigned int) k;
}

// largest x such that 2^x | a
static inline unsigned int ntz(unsigned int a) {
  int k = 0;
  while ((a % 2 == 0) && (a >>= 1))
    k++;
  return (unsigned int) k;
}
#endif

static inline void xor_16(unsigned char * __restrict a, const unsigned char * __restrict b) {
  for (int i = 0; i < 16; i++)
    a[i] ^= b[i];
}

static void hash(const unsigned char round_key[__restrict 240], const unsigned char *__restrict associated_data,
  unsigned int associated_data_length, const unsigned char l[__restrict][16],
  const unsigned char l_asterisk[__restrict 16], unsigned char out[__restrict 16]) {
  const int m = associated_data_length / 16;

  unsigned char offset[16] = {0};
  unsigned char cipher_temp[16];

  for (int i = 0; i < 16; i++)
    out[i] = 0;

  for (int i = 0; i < m; i++) {
    for (int k = 0; k < 16; k++)
      cipher_temp[k] = associated_data[i * 16 + k];
    xor_16(offset, l[ntz(i + 1)]);
    xor_16(cipher_temp, offset);
    cipher(cipher_temp, round_key);
    xor_16(out, cipher_temp);
  }

  const unsigned int a_asterisk_length = (unsigned int) (associated_data_length % 16);
  const unsigned int full_block_length = associated_data_length ^ a_asterisk_length;
  if (a_asterisk_length > 0) {
    xor_16(offset, l_asterisk);
    for (unsigned int i = 0; i < a_asterisk_length; i++)
      cipher_temp[i] = associated_data[full_block_length + i];
    cipher_temp[a_asterisk_length] = 0x80;
    for (int i = a_asterisk_length + 1; i < 16; i++)
      cipher_temp[i] = 0;
    xor_16(cipher_temp, offset);
    cipher(cipher_temp, round_key);
    xor_16(out, cipher_temp);
  }
}

void ocb_encrypt(const unsigned char key[__restrict 32], const unsigned char nonce[__restrict 15], unsigned int nonce_length,
  const unsigned char *__restrict message, unsigned int message_length, const unsigned char *__restrict associated_data,
  int associated_data_length, unsigned char *out) {
  const int m = message_length / 16;
  const unsigned int l_length =
    (message_length > associated_data_length) ?
    (ntz_round(m) + 1) :
    (ntz_round(associated_data_length / 16) + 1);
  unsigned char l[l_length][16];
  unsigned char l_asterisk[16] = {0};
  unsigned char l_dollar[16];
  unsigned char round_key[240];
  key_expansion(round_key, key);

  cipher(l_asterisk, round_key);
  // L_* ^^
  for (int i = 0; i < 16; i++)
    l[0][i] = l_asterisk[i];
  double_arr(l[0]);
  for (int i = 0; i < 16; i++)
    l_dollar[i] = l[0][i];
  double_arr(l[0]);
  // L_0 ^^^
  for (unsigned int i = 1; i < l_length; i++) {
    for (int k = 0; k < 16; k++)
      l[i][k] = l[i - 1][k];
    double_arr(l[i]);
  }
  unsigned char offset[24] = {0};
  int index = 15 - nonce_length;
  offset[index++] |= 1;
  for (unsigned int i = 0; i < nonce_length; index++, i++)
    offset[index] = nonce[i];
  unsigned int bottom = offset[15] % 64;
  offset[15] ^= bottom;
  cipher(offset, round_key);
  for (int i = 0; i < 8; i++)
    offset[16 + i] = offset[i];
  for (int i = 0; i < 8; i++)
    offset[16 + i] ^= offset[i + 1];

  const unsigned int shift = bottom / 8;
  const unsigned int bit_shift = bottom % 8;
  for (int i = 0; i < 16; i++)
    offset[i] = ((offset[i + shift] << bit_shift) | (offset[i + shift + 1] >> (8 - bit_shift))) & 255;

#ifdef __GNUC__
    __builtin_memcpy(out, message, message_length);
#else
    for (int i = 0; i < message_length; i++)
      out[i] = message[i];
#endif

  for (int i = 0; i < m; i++) {
    xor_16(offset, l[ntz(i + 1)]);
    xor_16(&out[i * 16], offset);
    cipher(&out[i * 16], round_key);
    xor_16(&out[i * 16], offset);
  }

  const unsigned int p_asterisk_length = (unsigned int) (message_length % 16);
  const unsigned int full_block_length = message_length ^ p_asterisk_length;
  unsigned char checksum[16] = {0};

  for (unsigned int i = 0; i < full_block_length; i++)
    checksum[i % 16] ^= message[i];

  if (p_asterisk_length > 0) {
    xor_16(offset, l_asterisk);
    for (int i = 0; i < 16; i++)
      out[full_block_length + i] = offset[i];
    cipher(&out[full_block_length], round_key);
    // ^^pad
    for (unsigned int i = 0; i < p_asterisk_length; i++)
      out[full_block_length + i] ^= message[full_block_length + i];
    for (unsigned int i = 0; i < p_asterisk_length; i++)
      checksum[i] ^= message[full_block_length + i];
    checksum[p_asterisk_length] ^= 0x80;
  }
  xor_16(checksum, offset);
  xor_16(checksum, l_dollar);
  cipher(checksum, round_key);
  hash(round_key, associated_data, associated_data_length, l, l_asterisk, offset);
  xor_16(checksum, offset);
  for (int i = 0; i < 16; i++)
    out[full_block_length + p_asterisk_length + i] = checksum[i];
}

int ocb_decrypt(const unsigned char key[__restrict 32], const unsigned char nonce[__restrict 15], unsigned int nonce_length,
  const unsigned char *__restrict encrypted, unsigned int encrypted_length, const unsigned char *__restrict associated_data,
  int associated_data_length, unsigned char *__restrict out) {
  const int m = encrypted_length / 16;
  const unsigned int l_length =
    (encrypted_length > associated_data_length) ?
    (ntz_round(m) + 1) :
    (ntz_round(associated_data_length / 16) + 1);
  unsigned char l[l_length][16];
  unsigned char l_asterisk[16] = {0};
  unsigned char l_dollar[16];
  unsigned char round_key[240];
  key_expansion(round_key, key);

  cipher(l_asterisk, round_key);
  // L_* ^^
  for (int i = 0; i < 16; i++)
    l[0][i] = l_asterisk[i];
  double_arr(l[0]);
  for (int i = 0; i < 16; i++)
    l_dollar[i] = l[0][i];
  double_arr(l[0]);
  // L_0 ^^^
  for (unsigned int i = 1; i < l_length; i++) {
    for (int k = 0; k < 16; k++)
      l[i][k] = l[i - 1][k];
    double_arr(l[i]);
  }
  unsigned char offset[24] = {0};
  int index = 15 - nonce_length;
  offset[index++] |= 1;
  for (unsigned int i = 0; i < nonce_length; index++, i++)
    offset[index] = nonce[i];
  unsigned int bottom = offset[15] % 64;
  offset[15] ^= bottom;
  cipher(offset, round_key);
  for (int i = 0; i < 8; i++)
    offset[16 + i] = offset[i];
  for (int i = 0; i < 8; i++)
    offset[16 + i] ^= offset[i + 1];

  const unsigned int shift = bottom / 8;
  const unsigned int bit_shift = bottom % 8;
  for (int i = 0; i < 16; i++)
    offset[i] = ((offset[i + shift] << bit_shift) | (offset[i + shift + 1] >> (8 - bit_shift))) & 255;

  const unsigned int c_asterisk_length = (unsigned int) (encrypted_length % 16);
  const unsigned int full_block_length = encrypted_length ^ c_asterisk_length;


#ifdef __GNUC__
  __builtin_memcpy(out, encrypted, full_block_length);
#else
  for (int i = 0; i < full_block_length; i++)
    out[i] = encrypted[i];
#endif
  for (int i = 0; i < m; i++) {
    xor_16(offset, l[ntz(i + 1)]);
    xor_16(&out[i * 16], offset);
    decipher(&out[i * 16], round_key);
    xor_16(&out[i * 16], offset);
  }

  unsigned char checksum[16] = {0};

  for (unsigned int i = 0; i < full_block_length; i++)
    checksum[i % 16] ^= out[i];

  if (c_asterisk_length > 0) {
    xor_16(offset, l_asterisk);
    unsigned char pad[16];
    for (int i = 0; i < 16; i++)
      pad[i] = offset[i];
    cipher(pad, round_key);
    // ^^pad
    for (unsigned int i = 0; i < c_asterisk_length; i++)
      pad[i] ^= encrypted[full_block_length + i];
    for (unsigned int i = 0; i < c_asterisk_length; i++)
      out[full_block_length + i] = pad[i];
    // ^^p_asterisk
    for (unsigned int i = 0; i < c_asterisk_length; i++)
      checksum[i] ^= pad[i];
    checksum[c_asterisk_length] ^= 0x80;
  }
  xor_16(checksum, offset);
  xor_16(checksum, l_dollar);
  cipher(checksum, round_key);
  hash(round_key, associated_data, associated_data_length, l, l_asterisk, offset);
  xor_16(checksum, offset);
  unsigned char diff = 0;
  for (unsigned int i = 0; i < 16; i++)
    diff ^= checksum[i];
  for (unsigned int i = 0; i < 16; i++)
    diff ^= encrypted[encrypted_length + i];
  return (unsigned int) diff;
}
