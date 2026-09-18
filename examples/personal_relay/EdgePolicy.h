#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include <helpers/IdentityStore.h>   // FILESYSTEM

// Maximum number of owner identities (companion devices) this relay serves.
#ifndef EDGE_MAX_OWNERS
#define EDGE_MAX_OWNERS  8
#endif
// Maximum number of group channel hashes mirrored to owners.
#ifndef EDGE_MAX_CHANNELS
#define EDGE_MAX_CHANNELS  8
#endif

// Filesystem path of the persisted policy.
#define EDGE_POLICY_FILE  "/edge_policy"

// Local-copy rate limit: at most this many zero-hop copies per window.
#define EDGE_LOCAL_COPY_MAX    30
#define EDGE_LOCAL_COPY_WINDOW_MS  60000UL

/**
 * Edge-relay packet policy.
 *
 * This is the "directional firewall" for the personal edge relay: it decides,
 * for every received packet, whether stock MeshCore handling may proceed
 * (EDGE_STOCK), whether the packet's payload should be re-emitted once as a
 * local zero-hop copy for nearby owners (EDGE_LOCAL_COPY), or whether the
 * packet must be dropped outright (EDGE_DROP).
 *
 * The classifier is intentionally pure (no side effects): rate-limit tokens
 * are consumed separately via tryLocalCopy() only when a copy is actually made.
 */
enum EdgeAction {
  EDGE_STOCK,       // hand to stock Mesh::onRecvPacket()
  EDGE_LOCAL_COPY,  // re-emit payload once as zero-hop direct; drop the original
  EDGE_DROP         // drop the packet entirely
};

struct EdgePolicyStats {
  uint32_t n_owner_uplink;  // owner floods forwarded via the stock path
  uint32_t n_local_copy;    // inbound floods re-emitted as local zero-hop copies
  uint32_t n_direct_fwd;    // owner-associated direct packets forwarded via stock
  uint32_t n_dropped;       // packets dropped by policy
};

class EdgePolicy {
  uint8_t _owner_keys[EDGE_MAX_OWNERS][PUB_KEY_SIZE];
  uint8_t _num_owners;
  uint8_t _channel_hashes[EDGE_MAX_CHANNELS];
  uint8_t _num_channels;
  bool _mirror_adverts;   // re-emit selected remote adverts locally (default: false)
  bool _fwd_acks;         // forward ACKs naming this node (default: false)
  bool _valid;            // false -> fail closed (receive-only)

  // sliding-window rate limiter for local copies
  uint32_t _rl_start_ms;
  uint16_t _rl_count;

public:
  EdgePolicy();

  // --- persistence ---
  bool load(FILESYSTEM* fs);   // false -> policy invalid, fail closed
  bool save(FILESYSTEM* fs);

  bool isValid() const { return _valid; }

  // --- owner / channel management ---
  int addOwner(const uint8_t pubkey[PUB_KEY_SIZE]);  // returns idx, or -1 if full/duplicate
  bool removeOwner(const uint8_t pubkey[PUB_KEY_SIZE]);
  int addChannel(uint8_t hash1);                     // returns idx, or -1 if full/duplicate
  bool removeChannel(uint8_t hash1);
  void setMirrorAdverts(bool v) { _mirror_adverts = v; }
  void setFwdAcks(bool v) { _fwd_acks = v; }
  bool getMirrorAdverts() const { return _mirror_adverts; }
  bool getFwdAcks() const { return _fwd_acks; }
  uint8_t getNumOwners() const { return _num_owners; }
  uint8_t getNumChannels() const { return _num_channels; }
  const uint8_t* getOwnerKey(int i) const { return _owner_keys[i]; }
  uint8_t getChannelHash(int i) const { return _channel_hashes[i]; }

  bool isOwnerHash(uint8_t h) const;
  bool isOwnerPubkey(const uint8_t pubkey[PUB_KEY_SIZE]) const;
  bool isChannel(uint8_t h) const;

  // --- classification ---
  // self_hash/self_hash_len: this node's path hash, for direct next-hop checks.
  EdgeAction classify(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const;

  // Final deny guard for allowPacketForward(): true only if stock handling is permitted.
  bool checkForward(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const {
    return _valid && classify(pkt, self_hash, self_hash_len) == EDGE_STOCK;
  }

  // Rate limiter: call when actually making a local copy.
  bool tryLocalCopy(uint32_t now_ms);
};
