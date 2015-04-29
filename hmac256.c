/* hmac256.c - Standalone HMAC implementation
 * Copyright (C) 2003, 2006, 2008  Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
    This is a standalone HMAC-SHA-256 implementation based on the code
    from ../cipher/sha256.c.  It is a second implementation to allow
    comparing against the standard implementations and to be used for
    internal consistency checks.  It should not be used for sensitive
    data because no mechanisms to clear the stack etc are used.

    This module may be used standalone and requires only a few
    standard definitions to be provided in a config.h file.

    Types:

     u32 - unsigned 32 bit type.

    Constants:

     WORDS_BIGENDIAN       Defined to 1 on big endian systems.
     inline                If defined, it should yield the keyword used
                           to inline a function.
     HAVE_U32_TYPEDEF      Defined if the u32 type is available.
     SIZEOF_UNSIGNED_INT   Defined to the size in bytes of an unsigned int.
     SIZEOF_UNSIGNED_LONG  Defined to the size in bytes of an unsigned long.

     STANDALONE            Compile a test driver similar to the
                           sha1sum tool.  This driver uses a self-test
                           identically to the one used by Libcgrypt
                           for testing this included module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#if defined(__WIN32) && defined(STANDALONE)
# include <fcntl.h> /* We need setmode().  */
#endif

/* For a native WindowsCE binary we need to include gpg-error.h to
   provide a replacement for strerror.  In other cases we need a
   replacement macro for gpg_err_set_errno.  */
#ifdef __MINGW32CE__
# include <gpg-error.h>
#else
# define gpg_err_set_errno(a) (errno = (a))
#endif

#include "hmac256.h"
#include "config.h"

#ifndef HAVE_U32_TYPEDEF
# undef u32 /* Undef a possible macro with that name.  */
# if SIZEOF_UNSIGNED_INT == 4
   typedef unsigned int u32;
# elif SIZEOF_UNSIGNED_LONG == 4
   typedef unsigned long u32;
# else
#  error no typedef for u32
# endif
# define HAVE_U32_TYPEDEF
#endif


/* The context used by this module.  */
struct hmac256_context
{
  u32  h0, h1, h2, h3, h4, h5, h6, h7;
  u32  nblocks;
  int  count;
  int  finalized:1;
  int  use_hmac:1;
  unsigned char buf[64];
  unsigned char opad[64];
};


/* Rotate a 32 bit word.  */
static inline u32 ror(u32 x, int n)
{
	return ( ((x) >> (n)) | ((x) << (32-(n))) );
}

#define my_wipememory2(_ptr,_set,_len) do { \
              volatile char *_vptr=(volatile char *)(_ptr); \
              size_t _vlen=(_len); \
              while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
                  } while(0)
#define my_wipememory(_ptr,_len) my_wipememory2(_ptr,0,_len)


/*
    The SHA-256 core: Transform the message X which consists of 16
    32-bit-words. See FIPS 180-2 for details.
 */
static void
transform (hmac256_context_t hd, const void *data_arg)
{
  const unsigned char *data = data_arg;

#define Cho(x,y,z) (z ^ (x & (y ^ z)))      /* (4.2) same as SHA-1's F1 */
#define Maj(x,y,z) ((x & y) | (z & (x|y)))  /* (4.3) same as SHA-1's F3 */
#define Sum0(x) (ror ((x), 2) ^ ror ((x), 13) ^ ror ((x), 22))  /* (4.4) */
#define Sum1(x) (ror ((x), 6) ^ ror ((x), 11) ^ ror ((x), 25))  /* (4.5) */
#define S0(x) (ror ((x), 7) ^ ror ((x), 18) ^ ((x) >> 3))       /* (4.6) */
#define S1(x) (ror ((x), 17) ^ ror ((x), 19) ^ ((x) >> 10))     /* (4.7) */
#define R(a,b,c,d,e,f,g,h,k,w) do                                 \
          {                                                       \
            t1 = (h) + Sum1((e)) + Cho((e),(f),(g)) + (k) + (w);  \
            t2 = Sum0((a)) + Maj((a),(b),(c));                    \
            h = g;                                                \
            g = f;                                                \
            f = e;                                                \
            e = d + t1;                                           \
            d = c;                                                \
            c = b;                                                \
            b = a;                                                \
            a = t1 + t2;                                          \
          } while (0)

  static const u32 K[64] =
    {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

  u32 a, b, c, d, e, f, g, h, t1, t2;
  u32 x[16];
  u32 w[64];
  int i;

  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef WORDS_BIGENDIAN
  memcpy (x, data, 64);
#else /*!WORDS_BIGENDIAN*/
  {
    unsigned char *p2;

    for (i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
      {
        p2[3] = *data++;
        p2[2] = *data++;
        p2[1] = *data++;
        p2[0] = *data++;
      }
  }
#endif /*!WORDS_BIGENDIAN*/

  for (i=0; i < 16; i++)
    w[i] = x[i];
  for (; i < 64; i++)
    w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

  for (i=0; i < 64; i++)
    R(a,b,c,d,e,f,g,h,K[i],w[i]);

  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}
#undef Cho
#undef Maj
#undef Sum0
#undef Sum1
#undef S0
#undef S1
#undef R


/*  Finalize the current SHA256 calculation.  */
static void
finalize (hmac256_context_t hd)
{
  u32 t, msb, lsb;
  unsigned char *p;

  if (hd->finalized)
    return; /* Silently ignore a finalized context.  */

  _gcry_hmac256_update (hd, NULL, 0); /* Flush.  */

  t = hd->nblocks;
  /* Multiply by 64 to make a byte count. */
  lsb = t << 6;
  msb = t >> 26;
  /* Add the count. */
  t = lsb;
  if ((lsb += hd->count) < t)
    msb++;
  /* Multiply by 8 to make a bit count. */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (hd->count < 56)
    { /* Enough room.  */
      hd->buf[hd->count++] = 0x80; /* pad */
      while (hd->count < 56)
        hd->buf[hd->count++] = 0;  /* pad */
    }
  else
    { /* Need one extra block. */
      hd->buf[hd->count++] = 0x80; /* pad character */
      while (hd->count < 64)
        hd->buf[hd->count++] = 0;
      _gcry_hmac256_update (hd, NULL, 0);  /* Flush.  */;
      memset (hd->buf, 0, 56 ); /* Zero out next next block.  */
    }
  /* Append the 64 bit count. */
  hd->buf[56] = msb >> 24;
  hd->buf[57] = msb >> 16;
  hd->buf[58] = msb >>  8;
  hd->buf[59] = msb;
  hd->buf[60] = lsb >> 24;
  hd->buf[61] = lsb >> 16;
  hd->buf[62] = lsb >>  8;
  hd->buf[63] = lsb;
  transform (hd, hd->buf);

  /* Store the digest into hd->buf.  */
  p = hd->buf;
#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
		  *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
  X(5);
  X(6);
  X(7);
#undef X
  hd->finalized = 1;
}



/* Create a new context.  On error NULL is returned and errno is set
   appropriately.  If KEY is given the function computes HMAC using
   this key; with KEY given as NULL, a plain SHA-256 digest is
   computed.  */
hmac256_context_t
_gcry_hmac256_new (const void *key, size_t keylen)
{
  hmac256_context_t hd;

  hd = malloc (sizeof *hd);
  if (!hd)
    return NULL;

  hd->h0 = 0x6a09e667;
  hd->h1 = 0xbb67ae85;
  hd->h2 = 0x3c6ef372;
  hd->h3 = 0xa54ff53a;
  hd->h4 = 0x510e527f;
  hd->h5 = 0x9b05688c;
  hd->h6 = 0x1f83d9ab;
  hd->h7 = 0x5be0cd19;
  hd->nblocks = 0;
  hd->count = 0;
  hd->finalized = 0;
  hd->use_hmac = 0;

  if (key)
    {
      int i;
      unsigned char ipad[64];

      memset (ipad, 0, 64);
      memset (hd->opad, 0, 64);
      if (keylen <= 64)
        {
          memcpy (ipad, key, keylen);
          memcpy (hd->opad, key, keylen);
        }
      else
        {
          hmac256_context_t tmphd;

          tmphd = _gcry_hmac256_new (NULL, 0);
          if (!tmphd)
            {
              free (hd);
              return NULL;
            }
          _gcry_hmac256_update (tmphd, key, keylen);
          finalize (tmphd);
          memcpy (ipad, tmphd->buf, 32);
          memcpy (hd->opad, tmphd->buf, 32);
          _gcry_hmac256_release (tmphd);
        }
      for (i=0; i < 64; i++)
        {
          ipad[i] ^= 0x36;
          hd->opad[i] ^= 0x5c;
        }
      hd->use_hmac = 1;
      _gcry_hmac256_update (hd, ipad, 64);
      my_wipememory (ipad, 64);
    }

  return hd;
}

/* Release a context created by _gcry_hmac256_new.  CTX may be NULL
   in which case the function does nothing.  */
void
_gcry_hmac256_release (hmac256_context_t ctx)
{
  if (ctx)
    {
      /* Note: We need to take care not to modify errno.  */
      if (ctx->use_hmac)
        my_wipememory (ctx->opad, 64);
      free (ctx);
    }
}


/* Update the message digest with the contents of BUFFER containing
   LENGTH bytes.  */
void
_gcry_hmac256_update (hmac256_context_t hd,
                        const void *buffer, size_t length)
{
  const unsigned char *inbuf = buffer;

  if (hd->finalized)
    return; /* Silently ignore a finalized context.  */

  if (hd->count == 64)
    {
      /* Flush the buffer. */
      transform (hd, hd->buf);
      hd->count = 0;
      hd->nblocks++;
    }
  if (!inbuf)
    return;  /* Only flushing was requested. */
  if (hd->count)
    {
      for (; length && hd->count < 64; length--)
        hd->buf[hd->count++] = *inbuf++;
      _gcry_hmac256_update (hd, NULL, 0); /* Flush.  */
      if (!length)
        return;
    }


  while (length >= 64)
    {
      transform (hd, inbuf);
      hd->count = 0;
      hd->nblocks++;
      length -= 64;
      inbuf += 64;
    }
  for (; length && hd->count < 64; length--)
    hd->buf[hd->count++] = *inbuf++;
}


/* Finalize an operation and return the digest.  If R_DLEN is not NULL
   the length of the digest will be stored at that address.  The
   returned value is valid as long as the context exists.  On error
   NULL is returned. */
const void *
_gcry_hmac256_finalize (hmac256_context_t hd, size_t *r_dlen)
{
  finalize (hd);
  if (hd->use_hmac)
    {
      hmac256_context_t tmphd;

      tmphd = _gcry_hmac256_new (NULL, 0);
      if (!tmphd)
        {
          free (hd);
          return NULL;
        }
      _gcry_hmac256_update (tmphd, hd->opad, 64);
      _gcry_hmac256_update (tmphd, hd->buf, 32);
      finalize (tmphd);
      memcpy (hd->buf, tmphd->buf, 32);
      _gcry_hmac256_release (tmphd);
    }
  if (r_dlen)
    *r_dlen = 32;
  return (void*)hd->buf;
}


/* Convenience function to compute the HMAC-SHA256 of one file.  The
   user needs to provide a buffer RESULT of at least 32 bytes, he
   needs to put the size of the buffer into RESULTSIZE and the
   FILENAME.  KEY and KEYLEN are as described for _gcry_hmac256_new.
   On success the function returns the valid length of the result
   buffer (which will be 32) or -1 on error.  On error ERRNO is set
   appropriate.  */
int
_gcry_hmac256_file (void *result, size_t resultsize, const char *filename,
                    const void *key, size_t keylen)
{
  FILE *fp;
  hmac256_context_t hd;
  size_t buffer_size, nread, digestlen;
  char *buffer;
  const unsigned char *digest;

  fp = fopen (filename, "rb");
  if (!fp)
    return -1;

  hd = _gcry_hmac256_new (key, keylen);
  if (!hd)
    {
      fclose (fp);
      return -1;
    }

  buffer_size = 32768;
  buffer = malloc (buffer_size);
  if (!buffer)
    {
      fclose (fp);
      _gcry_hmac256_release (hd);
      return -1;
    }

  while ( (nread = fread (buffer, 1, buffer_size, fp)))
    _gcry_hmac256_update (hd, buffer, nread);

  free (buffer);

  if (ferror (fp))
    {
      fclose (fp);
      _gcry_hmac256_release (hd);
      return -1;
    }

  fclose (fp);

  digest = _gcry_hmac256_finalize (hd, &digestlen);
  if (!digest)
    {
      _gcry_hmac256_release (hd);
      return -1;
    }

  if (digestlen > resultsize)
    {
      _gcry_hmac256_release (hd);
      gpg_err_set_errno (EINVAL);
      return -1;
    }
  memcpy (result, digest, digestlen);
  _gcry_hmac256_release (hd);

  return digestlen;
}
