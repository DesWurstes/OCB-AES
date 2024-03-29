## OCB AES

**Note: The AES code is taken from tiny-aes-c and the OCB code is written by me. This project is to demonstrate the OCB code here. tiny-aes-c cannot give constant-time guarantees hence replace tiny-aes-c in this project with Intel or Arm intrinsics or another safe AES implementation or use at your own risk**

This is a pure C implementation of AES. It is in [OCB 3](http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#versions) mode, which is the **best** AES mode!

Strongest parameters of the strongest algorithm: This code is only for 256 bit keys. Besides, it has TAGLEN of 128 bits.

> OCB is by far the best mode, as it allows encryption and authentication in a single pass.

~ [StackOverflow, user myforwik](https://stackoverflow.com/a/1220869)

> [OCB is] Usually much faster—like a factor of 2-6 [compared to other AES modes]...

~ [Phillip Rogaway, OCB developer](http://web.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#performance)

See the top of main.c for the notes about patents. It's actually pretty "free" software patent!

My work on coding it? I've made my work public domain! Have a nice day using it!

Timing-attack proof. Everything is constant time, as long as the data length, nonce length, and associated data length is constant.

> Using constant-time blockcipher and double() implementations eliminates most (if not all) sources of timing attacks on OCB.

~ [P. Rogaway and T. Krovetz](https://tools.ietf.org/pdf/rfc7253.pdf#20)

- No `#include` for simplicity

- Single-header

- Compatible with systems where `sizeof(char) > 1`

- Full name: `AEAD_AES_256_OCB_TAGLEN128`

### What is Associated Data?

So, do you know "proof of authenticity"? You can send one a message in plaintext,
then hash and sign it. It works the same way: You can add "associated data" as that
plaintext while encrypting. Your friend will need the know the associated data to decode the ciphertext.
If decoding succeeds, your friend will be sure that your associated data was untampered. (under some assumptions)

Furthermore, the associated data does not make the ciphertext longer.

If you don't use associated data, defining `OCB_NO_AD` will decrease the code size.

If the nonce length is constant, defining `OCB_CONST_NONCE` equal to the nonce length (max 15) will decrease the code size.

In above cases, the function parameters change. The header file can no longer guide you.
