/* Copyright 2012 exMULTI, Inc.
 * Copyright (c) 2009-2012 The Bitcoin developers
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>

#include <ccoin/key.h>

/* Generate a private key from just the secret parameter */
static bool bp_key_regenerate(struct bp_key *key, mpi *priv_key)
{
	/* TODO: Confirm the usefulness of this function or remove it */
	bool ret = false;
	ecp_point pub_key;

	if (!&key->pk)
		goto err_out;

	ecp_keypair *ecp = pk_ec(key->pk);

	ecp_point_init(&pub_key);

	if ( ecp_mul(&ecp->grp, &pub_key, priv_key, &ecp->grp.G, hmac_drbg_random, &key->c) !=0 )
		goto err_out;

	if ( ecp_copy(&ecp->Q, &pub_key) !=0 )
		goto err_out;

	ret = true;

err_out:
        ecp_point_free(&pub_key);
	return ret;
}

bool bp_key_init(struct bp_key *key)
{
	/* TODO: Add a more random personalised string */
	const char *pers = "bp_key_ecdsa";

	pk_init(&key->pk);
	entropy_init(&key->e);

	if( (hmac_drbg_init(&key->c, md_info_from_type(POLARSSL_MD_SHA1),
					entropy_func, &key->e,
					(const unsigned char *) pers,
					strlen(pers))) != 0 )
		return false;

	if( pk_init_ctx(&key->pk, pk_info_from_type(POLARSSL_PK_ECKEY)) != 0 )
		return false;

	return true;
}

void bp_key_free(struct bp_key *key)
{
	if (&key->pk) {
		pk_free(&key->pk);
	}
	if (&key->e) {
		entropy_free(&key->e);
	}
}

bool bp_key_generate(struct bp_key *key)
{
	if ( !&key->pk || !&key->e || !&key->c )
		return false;

	if( ecp_gen_key(ECPARAMS, pk_ec(key->pk), hmac_drbg_random, &key->c) != 0 )
		return false;

    /* TODO: Check if key is compressed or uncompressed */

	return true;
}

bool bp_privkey_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	const unsigned char *privkey = privkey_;
	int ret;

	if ( (ret = pk_parse_key(&key->pk, privkey, pk_len, NULL, 0)) != 0 )
		return false;

	if ( pk_can_do(&key->pk, POLARSSL_PK_ECDSA) != 1 )
		return false;

	return true;
}

bool bp_pubkey_set(struct bp_key *key, const void *pubkey_, size_t pk_len)
{
	const unsigned char *pubkey = pubkey_;
	ecp_keypair *ecp = pk_ec(key->pk);

	if ( ecp_use_known_dp( &ecp->grp, POLARSSL_ECP_DP_SECP256K1 ) != 0 )
		return false;

//	if ( ecp_point_read_binary( &ecp->grp, &ecp->Q, pubkey, pk_len ) != 0 )
	if ( ecp_point_read_binary_compressed( &ecp->grp, &ecp->Q, pubkey, pk_len ) != 0 )
		return false;

	if ( pk_can_do(&key->pk, POLARSSL_PK_ECDSA) != 1 )
		return false;

	return true;
}

bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	/* TODO: Confirm the usefulness of this function or remove it */

	bp_key_free(key);

	if (!privkey_ || pk_len != 32)
		return false;

	const unsigned char *privkey = privkey_;

	mpi bn;
	mpi_init(&bn);

	if ( mpi_read_binary(&bn, privkey, sizeof(privkey)) != 0)
		return false;

	if (!&key->pk)
		goto err;

	if (!bp_key_regenerate(key, &bn))
		goto err;

	ecp_keypair *ecp = pk_ec(key->pk);

	if ( ecp_check_privkey(&ecp->grp, &ecp->d) != 0 )
		goto err;

	if ( ecp_check_pubkey(&ecp->grp, &ecp->Q) != 0 )
		goto err;

	if ( pk_can_do(&key->pk, POLARSSL_PK_ECDSA) != 1 )
		goto err;

	mpi_free(&bn);

	return true;

err:
	bp_key_free(key);
	mpi_free(&bn);
	return false;
}

bool bp_privkey_get(struct bp_key *key, void **privkey, size_t *pk_len)
{
	ecp_keypair *ecp = pk_ec(key->pk);

	if ( ecp_check_privkey(&ecp->grp, &ecp->d) != 0 )
		return false;

	size_t buf_sz = POLARSSL_ECP_MAX_PT_LEN;
	int len;

	unsigned char *buf = malloc(buf_sz);

	if ( (len = pk_write_key_der(&key->pk, buf, buf_sz)) <= 0 )
		return false;

	unsigned char *privkey_ = malloc(len);
	memcpy(privkey_, buf + buf_sz - len, len);

	/* zero buffer */
	memset(buf, 0, buf_sz);

	*privkey = privkey_;
	*pk_len = len;

	return true;
}

bool bp_pubkey_get(struct bp_key *key, void **pubkey, size_t *pk_len)
{
	ecp_keypair *ecp = pk_ec(key->pk);

	if ( ecp_check_pubkey(&ecp->grp, &ecp->Q) != 0 )
		return false;

	size_t buf_sz = pk_get_len(&key->pk) + 1;
	size_t len;

	unsigned char *buf = malloc(buf_sz);

	if ( ecp_point_write_binary( &ecp->grp, &ecp->Q, POLARSSL_ECP_PF_COMPRESSED, &len, buf, buf_sz ) != 0 )
	    return false;

	*pubkey = buf;
	*pk_len = len;

	return true;
}

bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key)
{
	/* TODO: Confirm the usefulness of this function or remove it */

	if (!p || len < 32 || !key)
		return false;

	/* zero buffer */
	memset(p, 0, len);

	ecp_keypair *ecp = pk_ec(key->pk);

	/* get mpi secret */
	const mpi *bn = &ecp->d;
	if (!bn)
		return false;
	int nBytes = mpi_size(bn);

	/* store secret at end of buffer */
	if ( mpi_write_binary(bn, p + (len - nBytes), nBytes) != 0 )
		return false;

	return true;
}

bool bp_sign(struct bp_key *key, const void *data, size_t data_len,
	     void **sig_, size_t *sig_len_)
{
	size_t sig_sz = MAX_SIG_LEN;
	void *sig = calloc(1, sig_sz);
	size_t sig_sz_out = sig_sz;

	if ( pk_sign(&key->pk,
				 POLARSSL_MD_NONE,
				 data, data_len,
				 sig, &sig_sz_out,
				 hmac_drbg_random, &key->c) != 0 ) {
		free(sig);
		return false;
	}

	*sig_ = sig;
	*sig_len_ = sig_sz_out;

	return true;
}

bool bp_verify(struct bp_key *key, const void *data, size_t data_len,
	       const void *sig, size_t sig_len)
{
	bool is_valid = false;
	size_t len;

	// Loop until signature is correct length i.e. remove stuffed bytes
//	TODO: This can be done more efficiently by using POLARSSL_ERR_PK_SIG_LEN_MISMATCH
	for( len = sig_len; !is_valid && len > 0; len-- )
	{
		if ( pk_verify(&key->pk, POLARSSL_MD_NONE, data, data_len, sig, len) == 0 )
				is_valid = true;
	}

	return is_valid;
}

// TODO: This function can be removed if/when PolarSSL supports compressed points
// Single purpose read point in binary format, only support compressed secp256k1 point
int ecp_point_read_binary_compressed(const ecp_group *group, ecp_point *point, const unsigned char *buffer, size_t ilen) {
	int ret;
	unsigned char parity;
	size_t plen;
	mpi e, y2;

	mpi_init(&e); mpi_init(&y2);

	ret = ecp_point_read_binary(group, point, buffer, ilen);
	if (POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE != ret) {
		return ret;
	}

	if (POLARSSL_ECP_DP_SECP256K1 != group->id) {
		return POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE;
	}

	if (0x02 == buffer[0]) {
		parity = 0;
	} else if (0x03 == buffer[0]) {
		parity = 1;
	} else {
		return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
	}

	plen = mpi_size(&group->P);

	if (ilen != plen + 1) {
		return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
	}

	MPI_CHK(mpi_read_binary(&point->X, buffer + 1, plen));
	MPI_CHK(mpi_lset(&point->Z, 1));

	// Set y2 = X^3 + B
	MPI_CHK(mpi_mul_mpi(&y2, &point->X, &point->X));
	MPI_CHK(mpi_mod_mpi(&y2, &y2, &group->P));
	MPI_CHK(mpi_mul_mpi(&y2, &y2, &point->X));
	MPI_CHK(mpi_add_mpi(&y2, &y2, &group->B));
	MPI_CHK(mpi_mod_mpi(&y2, &y2, &group->P));

	// Compute square root of y2
	MPI_CHK(mpi_add_int(&e, &group->P, 1));
	MPI_CHK(mpi_shift_r(&e, 2));
	MPI_CHK(mpi_exp_mod(&point->Y, &y2, &e, &group->P, NULL));

	// Set parity
	if (mpi_get_bit(&point->Y, 0) != parity) {
		MPI_CHK(mpi_sub_mpi(&point->Y, &group->P, &point->Y));
	}

cleanup:
	mpi_free(&e);
	mpi_free(&y2);

	return ret;
}
