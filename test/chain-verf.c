/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buffer.h>               // for const_buffer
#include <ccoin/buint.h>                // for bu256_hex, BU256_STRSZ, etc
#include <ccoin/checkpoints.h>          // for bp_ckpt_last
#include <ccoin/core.h>                 // for bp_block, bp_tx, bp_utxo, etc
#include <ccoin/coredefs.h>             // for chain_info, etc
#include <ccoin/db/chaindb.h>           // for blkinfo, chaindb_reorg, etc
#include <ccoin/db/db.h>                // for blockdb_init, etc
#include <ccoin/key.h>                  // for bp_key_static_shutdown
#include <ccoin/log.h>                  // for logging
#include <ccoin/mbr.h>                  // for fread_block
#include <ccoin/message.h>              // for p2p_message, etc
#include <ccoin/parr.h>                 // for parr, parr_id
#include <ccoin/script.h>               // for bp_verify_sig
#include <ccoin/util.h>                 // for file_seq_open

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, false, bool
#include <stdint.h>                     // for int64_t
#include <stdio.h>                      // for fprintf, stderr, perror, etc
#include <stdlib.h>                     // for getenv, calloc, free
#include <string.h>                     // for memcmp, strncmp
#include <unistd.h>                     // for close

static bool no_script_verf = false;
static bool force_script_verf = false;
struct logging *log_state;

static bool spend_tx(struct bp_utxo_set *uset, const struct bp_tx *tx,
		     unsigned int tx_idx, unsigned int height,
		     unsigned int ckpt_height)
{
	assert(tx->sha256_valid == true);

	bool is_coinbase = (tx_idx == 0);

	struct bp_utxo *coin;

	int64_t total_in = 0, total_out = 0;

	unsigned int i;

	/* verify and spend this transaction's inputs */
	if (!is_coinbase) {
		for (i = 0; i < tx->vin->len; i++) {
			struct bp_txin *txin;
			struct bp_txout *txout;

			txin = parr_idx(tx->vin, i);

			coin = bp_utxo_lookup(uset, &txin->prevout.hash);
			if (!coin || !coin->vout)
				return false;

			if (coin->is_coinbase &&
			    ((coin->height + COINBASE_MATURITY) > height))
				return false;

			txout = NULL;
			if (txin->prevout.n >= coin->vout->len)
				return false;
			txout = parr_idx(coin->vout, txin->prevout.n);
			total_in += txout->nValue;

			bool check_script;
			if (force_script_verf)
				check_script = true;
			else if (no_script_verf)
				check_script = false;
			else if (height < ckpt_height)
				check_script = false;
			else
				check_script = true;

			if (check_script &&
			    !bp_verify_sig(coin, tx, i,
						/* SCRIPT_VERIFY_P2SH */ 0, 0))
				return false;

			if (!bp_utxo_spend(uset, &txin->prevout))
				return false;
		}
	}

	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = parr_idx(tx->vout, i);
		total_out += txout->nValue;
	}

	if (!is_coinbase) {
		if (total_out > total_in)
			return false;
	}

	/* copy-and-convert a tx into a UTXO */
	coin = calloc(1, sizeof(*coin));
	bp_utxo_init(coin);

	assert(bp_utxo_from_tx(coin, tx, is_coinbase, height) == true);

	/* add unspent outputs to set */
	bp_utxo_set_add(uset, coin);

	return true;
}

static bool spend_block(struct bp_utxo_set *uset, const struct bp_block *block,
			unsigned int height, unsigned int ckpt_height)
{
	unsigned int i;

	if (height % 5000 == 0)
		fprintf(stderr, "chain-verf: spend block @ %u\n", height);

	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = parr_idx(block->vtx, i);
		if (!spend_tx(uset, tx, i, height, ckpt_height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			fprintf(stderr,
				"chain-verf: tx fail %s\n", hexstr);
			return false;
		}
	}

	return true;
}

static void read_test_msg(struct chaindb *db, struct bp_utxo_set *uset,
			  const struct p2p_message *msg, int64_t fpos,
			  unsigned int ckpt_height)
{
	assert(strncmp(msg->hdr.command, "block",
		       sizeof(msg->hdr.command)) == 0);

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	assert(deser_bp_block(&block, &buf) == true);
	bp_block_calc_sha256(&block);

	assert(bp_block_valid(&block) == true);

	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block.sha256);
	bp_block_copy_hdr(&bi->hdr, &block);

	struct chaindb_reorg reorg;

	assert(chaindb_add(db, bi, &reorg) == true);

	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);

	/* if best chain, mark TX's as spent */
	if (bu256_equal(&db->best_chain->hash, &bi->hdr.sha256)) {
		if (!spend_block(uset, &block, bi->height, ckpt_height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &bi->hdr.sha256);
			fprintf(stderr,
				"chain-verf: block fail %u %s\n",
				bi->height, hexstr);
			assert(!"spend_block");
		}
	}

	bp_block_free(&block);
}

static void runtest(bool use_testnet, const char *blocks_fn)
{
	enum chains chain_id = use_testnet ? CHAIN_TESTNET3 : CHAIN_BITCOIN;
	const struct chain_info *chain = &chain_metadata[chain_id];

	unsigned int ckpt_height = bp_ckpt_last(chain_id);

	struct chaindb chaindb;
	bu256_t blk0;

	hex_bu256(&blk0, chain->genesis_hash);
	assert(metadb_init(chain_metadata[chain_id].netmagic, (const bu256_t *)chain_metadata[chain_id].genesis_hash));
	assert(blockdb_init());
	assert(blockheightdb_init());

	assert(chaindb_init(&chaindb, chain->netmagic, &blk0) == true);

	struct bp_utxo_set uset;
	bp_utxo_set_init(&uset);

	fprintf(stderr, "chain-verf: validating %s chainfile %s (%cscript)\n",
		use_testnet ? "testnet3" : "mainnet",
		blocks_fn,
		force_script_verf ? '+' :
		  no_script_verf ? '-' : '*');

	int fd = file_seq_open(blocks_fn);
	if (fd < 0) {
		perror(blocks_fn);
		assert(fd >= 0);
	}

	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
	unsigned int records = 0;
	while (fread_block(fd, &msg, &read_ok)) {
		assert(memcmp(msg.hdr.netmagic, chain->netmagic, 4) == 0);

		read_test_msg(&chaindb, &uset, &msg, fpos, ckpt_height);

		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
		records++;
	}

	assert(read_ok == true);

	close(fd);
	free(msg.data);

	chaindb_free(&chaindb);
	bp_utxo_set_free(&uset);

	fprintf(stderr, "chain-verf: %u records validated\n", records);
}

int main (int argc, char *argv[])
{
	char *fn;
	unsigned int verfd = 0;

	log_state = calloc(0, sizeof(struct logging));

	log_state->stream = stderr;
	log_state->logtofile = false;
	log_state->debug = true;

	if (getenv("NO_SCRIPT_VERF"))
		no_script_verf = true;
	if (getenv("FORCE_SCRIPT_VERF")) {
		no_script_verf = false;
		force_script_verf = true;
	}

	fn = getenv("TEST_TESTNET3_VERF");
	if (fn) {
		verfd++;
		runtest(true, fn);
	}

	fn = getenv("TEST_MAINNET_VERF");
	if (fn) {
		verfd++;
		runtest(false, fn);
	}

	if (!verfd) {
		fprintf(stderr,
	"chain-verf: Skipping lengthy, extended chain verification test.\n"
	"chain-verf: Set TEST_TESTNET3_VERF and/or TEST_MAINNET_VERF to a\n"
	"chain-verf: valid linearized bootstrap.dat file, to enable.\n"
	"chain-verf: NO_SCRIPT_VERF=1 to disable script verification\n"
	"chain-verf: FORCE_SCRIPT_VERF=1 to verify all scripts, even checkpointed\n"
			);
		return 77;
	}

	bp_key_static_shutdown();
	return 0;
}
