/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <polarssl/aes.h>
#include <polarssl/sha256.h>
#include <ccoin/aes.h>

GString *read_aes_file(const char *filename, void *key, size_t key_len)
{

#if defined(_WIN32_WCE)
	long filesize;
#elif defined(_WIN32)
	LARGE_INTEGER li_size;
	__int64 filesize;
#else
	off_t filesize;
#endif

	FILE *file;

	GString *rs = NULL;

	file = fopen(filename, "rb");

#if defined(_WIN32_WCE)
	filesize = fseek( fin, 0L, SEEK_END );
#else
#if defined(_WIN32)
	/*
	 * Support large files (> 2Gb) on Win32
	 */
	li_size.QuadPart = 0;
	li_size.LowPart  =
		SetFilePointer( (HANDLE) _get_osfhandle( _fileno( file ) ),
						li_size.LowPart, &li_size.HighPart, FILE_END );

	if( li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR )
	{
		fprintf( stderr, "aes: SetFilePointer(0,FILE_END) failed\n" );
		fclose( file );
		return rs;
	}

	filesize = li_size.QuadPart;
#else
	if( ( filesize = lseek( fileno( file ), 0, SEEK_END ) ) < 0 )
	{
		perror( "lseek" );
		fclose( file );
		return rs;
	}
#endif
#endif

	if( fseek( file, 0, SEEK_SET ) < 0 )
	{
		fprintf( stderr, "aes: fseek(0,SEEK_SET) failed\n" );
		fclose( file );
		return rs;
	}

	/*
	 *  The encrypted file must be structured as follows:
	 *
	 *        00 .. 15           Initialization Vector
	 *        16 .. N            AES Encrypted Block
	 *     N + 1 .. N + 1 + 32   HMAC-SHA-256(ciphertext)
	 */

	if( filesize < 48 )
	{
		fprintf( stderr, "aes: File too short to be decrypted.\n" );
		fclose( file );
		return rs;
	}

	if( ( filesize & 0x0f ) != 0 )
	{
		fprintf( stderr, "aes: File size not a multiple of 16.\n" );
		fclose( file );
		return rs;
	}

	/*
	 * Subtract the IV + HMAC length.
	 */
	filesize -= ( 16 + 32 );

	unsigned char IV[16];
	unsigned char buffer[filesize];
	unsigned char plaintext[filesize];
	unsigned char digest[32];
	unsigned char diff;

	int lastn, i;
	size_t pt_len;

	sha256_context sha_ctx;
	aes_context aes_ctx;

	/*
	 * Read the IV and original filesize modulo 16.
	 */
	if( fread( buffer, 1, 16, file ) != 16 )
	{
		fprintf( stderr, "aes: fread(%d bytes) failed\n", 16 );
		goto out;
	}

	memcpy( IV, buffer, 16 );
	lastn = IV[15] & 0x0f;
	pt_len = ( lastn == 0 ) ? filesize : filesize - 16 + lastn;

	/*
	 * Hash the IV and the secret key together 8192 times
	 * using the result to setup the AES context and HMAC.
	 */
	memset( digest, 0,  32 );
	memcpy( digest, IV, 16 );

	for( i = 0; i < 8192; i++ )
	{
		sha256_starts( &sha_ctx, 0 );
		sha256_update( &sha_ctx, digest, 32 );
		sha256_update( &sha_ctx, key, key_len );
		sha256_finish( &sha_ctx, digest );
	}

	aes_setkey_dec( &aes_ctx, digest, 256 );
	sha256_hmac_starts( &sha_ctx, digest, 32, 0 );

	/*
	 * Decrypt and write the plaintext.
	 */

	if( fread( buffer, 1, filesize, file ) != filesize )
	{
		fprintf( stderr, "aes: fread(%d bytes) failed\n", (int)filesize );
		goto out;
	}

	sha256_hmac_update( &sha_ctx, buffer, filesize );
	aes_crypt_cbc( &aes_ctx, AES_DECRYPT, filesize, IV, buffer, plaintext );

	/*
	 * Verify the message authentication code.
	 */
	sha256_hmac_finish( &sha_ctx, digest );

	if( fread( buffer, 1, 32, file ) != 32 )
	{
		fprintf( stderr, "aes: fread(%d bytes) failed\n", 32 );
		goto out;
	}

	/* Use constant-time buffer comparison */
	diff = 0;
	for( i = 0; i < 32; i++ )
		diff |= digest[i] ^ buffer[i];

	if( diff != 0 )
	{
		fprintf( stderr, "aes: HMAC check failed: wrong key, "
										"or file corrupted.\n" );
		goto out;
	}

	rs = g_string_new_len((char *)plaintext, pt_len);

out:
	memset( IV, 0, sizeof( IV ) );
	memset( buffer, 0, sizeof( buffer ) );
	memset( plaintext, 0, sizeof( plaintext ) );
	memset( digest, 0, sizeof( digest ) );

	memset( &aes_ctx, 0, sizeof(  aes_context ) );
	memset( &sha_ctx, 0, sizeof( sha256_context ) );

	if( filename )
		fclose( file );

	return rs;
}

bool write_aes_file(const char *filename, void *key, size_t key_len,
                    const void *plaintext, size_t pt_len)
{
	FILE *file;

	int lastn, i;
	// Round pt_len up to multiple of AES block size (16 bytes)
	int buf_len = (pt_len + 15) & ~0x0f;
	bool rc = false;

	unsigned char IV[16];
	unsigned char buffer[buf_len];
	unsigned char digest[32];

	sha256_context sha_ctx;
	aes_context aes_ctx;

	/*
	 * Generate the initialization vector as:
	 * IV = SHA-256( pt_len || filename )[0..15]
	 */
	for( i = 0; i < 8; i++ )
		buffer[i] = (unsigned char)( pt_len >> ( i << 3 ) );

	sha256_starts( &sha_ctx, 0 );
	sha256_update( &sha_ctx, buffer, 8 );
	sha256_update( &sha_ctx, (unsigned char *)filename, strlen( filename ) );
	sha256_finish( &sha_ctx, digest );

	memcpy( IV, digest, 16 );

	/*
	 * The last four bits in the IV are actually used
	 * to store the file size modulo the AES block size.
	 */
	lastn = (int)( pt_len & 0x0f );
	IV[15] = (unsigned char) ( ( IV[15] & 0xf0 ) | lastn );

	/*
	 * Append the IV at the beginning of the output.
	 */
	file = fopen(filename, "wb");

	if( fwrite( IV, 1, 16, file ) != 16 )
	{
		fprintf( stderr, "aes: fwrite(%d bytes) failed\n", 16 );
		goto out;
	}

	/*
	 * Hash the IV and the secret key together 8192 times
	 * using the result to setup the AES context and HMAC.
	 */
	memset( digest, 0,  32 );
	memcpy( digest, IV, 16 );

	for( i = 0; i < 8192; i++ )
	{
		sha256_starts( &sha_ctx, 0 );
		sha256_update( &sha_ctx, digest, 32 );
		sha256_update( &sha_ctx, key, key_len );
		sha256_finish( &sha_ctx, digest );
	}

	memset( key, 0, sizeof( key ) );
	aes_setkey_enc( &aes_ctx, digest, 256 );
	sha256_hmac_starts( &sha_ctx, digest, 32, 0 );

	/*
	 * Encrypt and write the ciphertext.
	 */
	aes_crypt_cbc( &aes_ctx, AES_ENCRYPT, buf_len, IV, plaintext, buffer );
	sha256_hmac_update( &sha_ctx, buffer, buf_len );

	if( fwrite( buffer, 1, buf_len, file ) != buf_len )
	{
		fprintf( stderr, "aes: fwrite(%d bytes) failed\n", (int)pt_len );
		goto out;
	}

	/*
	 * Finally write the HMAC.
	 */
	sha256_hmac_finish( &sha_ctx, digest );

	if( fwrite( digest, 1, 32, file ) != 32 )
	{
		fprintf( stderr, "aes: fwrite(%d bytes) failed\n", 16 );
		goto out;
	}

	rc = true;

out:
	memset( IV, 0, sizeof( IV ) );
	memset( buffer, 0, sizeof( buffer ) );
	memset( digest, 0, sizeof( digest ) );
	memset( key, 0, sizeof( key ) );

	memset( &aes_ctx, 0, sizeof(  aes_context ) );
	memset( &sha_ctx, 0, sizeof( sha256_context ) );

	if( filename )
		fclose( file );

	return rc;
}
