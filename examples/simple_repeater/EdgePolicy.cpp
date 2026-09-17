#include "EdgePolicy.h"

EdgePolicy::EdgePolicy() {
  _num_owners = 0;
  _num_channels = 0;
  _mirror_adverts = false;
  _fwd_acks = false;
  _valid = false;   // no policy loaded yet -> fail closed until load() succeeds
  _rl_start_ms = 0;
  _rl_count = 0;
  memset(_owner_keys, 0, sizeof(_owner_keys));
  memset(_channel_hashes, 0, sizeof(_channel_hashes));
}

bool EdgePolicy::isOwnerHash(uint8_t h) const {
  // The 1-byte wire hash is the first byte of the Ed25519 public key.
  for (int i = 0; i < _num_owners; i++) {
    if (_owner_keys[i][0] == h) return true;
  }
  return false;
}

bool EdgePolicy::isOwnerPubkey(const uint8_t pubkey[PUB_KEY_SIZE]) const {
  for (int i = 0; i < _num_owners; i++) {
    if (memcmp(_owner_keys[i], pubkey, PUB_KEY_SIZE) == 0) return true;
  }
  return false;
}

bool EdgePolicy::isChannel(uint8_t h) const {
  for (int i = 0; i < _num_channels; i++) {
    if (_channel_hashes[i] == h) return true;
  }
  return false;
}

int EdgePolicy::addOwner(const uint8_t pubkey[PUB_KEY_SIZE]) {
  if (isOwnerPubkey(pubkey)) return -1;  // duplicate
  if (_num_owners >= EDGE_MAX_OWNERS) return -1;
  memcpy(_owner_keys[_num_owners], pubkey, PUB_KEY_SIZE);
  return _num_owners++;
}

bool EdgePolicy::removeOwner(const uint8_t pubkey[PUB_KEY_SIZE]) {
  for (int i = 0; i < _num_owners; i++) {
    if (memcmp(_owner_keys[i], pubkey, PUB_KEY_SIZE) == 0) {
      // compact the list
      for (int j = i; j < _num_owners - 1; j++) {
        memcpy(_owner_keys[j], _owner_keys[j + 1], PUB_KEY_SIZE);
      }
      _num_owners--;
      return true;
    }
  }
  return false;
}

int EdgePolicy::addChannel(uint8_t hash1) {
  if (isChannel(hash1)) return -1;
  if (_num_channels >= EDGE_MAX_CHANNELS) return -1;
  _channel_hashes[_num_channels] = hash1;
  return _num_channels++;
}

bool EdgePolicy::removeChannel(uint8_t hash1) {
  for (int i = 0; i < _num_channels; i++) {
    if (_channel_hashes[i] == hash1) {
      for (int j = i; j < _num_channels - 1; j++) {
        _channel_hashes[j] = _channel_hashes[j + 1];
      }
      _num_channels--;
      return true;
    }
  }
  return false;
}

bool EdgePolicy::tryLocalCopy(uint32_t now_ms) {
  if (now_ms - _rl_start_ms >= EDGE_LOCAL_COPY_WINDOW_MS) {
    _rl_start_ms = now_ms;
    _rl_count = 0;
  }
  if (_rl_count >= EDGE_LOCAL_COPY_MAX) return false;
  _rl_count++;
  return true;
}

static bool isFloodRoute(uint8_t route) {
  return route == ROUTE_TYPE_FLOOD || route == ROUTE_TYPE_TRANSPORT_FLOOD;
}

static bool isDirectRoute(uint8_t route) {
  return route == ROUTE_TYPE_DIRECT || route == ROUTE_TYPE_TRANSPORT_DIRECT;
}

EdgeAction EdgePolicy::classify(const mesh::Packet* pkt, const uint8_t* self_hash, uint8_t self_hash_len) const {
  if (!_valid) return EDGE_DROP;  // fail closed: receive-only

  uint8_t route = pkt->getRouteType();
  uint8_t ptype = pkt->getPayloadType();
  uint8_t path_count = pkt->getPathHashCount();

  if (isFloodRoute(route)) {
    switch (ptype) {
      case PAYLOAD_TYPE_TXT_MSG:
      case PAYLOAD_TYPE_REQ:
      case PAYLOAD_TYPE_RESPONSE:
      case PAYLOAD_TYPE_PATH: {
        if (pkt->payload_len < 2) return EDGE_DROP;
        uint8_t dest_hash = pkt->payload[0];
        uint8_t src_hash = pkt->payload[1];
        if (path_count == 0) {
          // Directly heard (zero-hop). Only an owner's own transmission may enter
          // the stock flood path; anything else is foreign transit.
          // The empty-path requirement keeps a packet already circulating in the
          // mesh from being mistaken for a local owner transmission.
          return isOwnerHash(src_hash) ? EDGE_STOCK : EDGE_DROP;
        }
        // Already circulating: deliver a local copy if it is addressed to an owner.
        return isOwnerHash(dest_hash) ? EDGE_LOCAL_COPY : EDGE_DROP;
      }
      case PAYLOAD_TYPE_GRP_TXT:
      case PAYLOAD_TYPE_GRP_DATA: {
        if (pkt->payload_len < 1) return EDGE_DROP;
        uint8_t ch = pkt->payload[0];
        if (!isChannel(ch)) return EDGE_DROP;
        // Configured channel: owner opted in. Outbound (zero-hop) group traffic
        // goes through the normal flood path; inbound floods get a local copy.
        return path_count == 0 ? EDGE_STOCK : EDGE_LOCAL_COPY;
      }
      case PAYLOAD_TYPE_ADVERT: {
        if (pkt->payload_len < PUB_KEY_SIZE) return EDGE_DROP;
        // Never export an owner's advert outward: that would publish a route
        // through this moving relay.
        if (isOwnerPubkey(pkt->payload)) return EDGE_DROP;
        // Optional one-way discovery: mirror selected remote adverts locally.
        // Disabled by default.
        if (_mirror_adverts && path_count > 0) return EDGE_LOCAL_COPY;
        return EDGE_DROP;
      }
      case PAYLOAD_TYPE_ACK: {
        // ACKs carry no attributable owner identity; default is to drop.
        return _fwd_acks ? EDGE_STOCK : EDGE_DROP;
      }
      default:
        // ANON_REQ, TRACE, CONTROL, MULTIPART, RAW_CUSTOM, unknown: drop.
        return EDGE_DROP;
    }
  }

  if (isDirectRoute(route)) {
    if (path_count == 0) {
      // Zero-hop direct: link-local only. Allow control (e.g. discovery replies)
      // through stock handling; they cannot propagate. Everything else: drop.
      return ptype == PAYLOAD_TYPE_CONTROL ? EDGE_STOCK : EDGE_DROP;
    }
    // This node must be the named next hop, or the packet is not ours to touch.
    uint8_t hash_len = pkt->getPathHashSize();
    if (hash_len > self_hash_len) return EDGE_DROP;
    if (memcmp(pkt->path, self_hash, hash_len) != 0) return EDGE_DROP;

    switch (ptype) {
      case PAYLOAD_TYPE_TXT_MSG:
      case PAYLOAD_TYPE_REQ:
      case PAYLOAD_TYPE_RESPONSE:
      case PAYLOAD_TYPE_PATH: {
        if (pkt->payload_len < 2) return EDGE_DROP;
        // Forward only owner-associated direct traffic; stock consumes our path
        // entry exactly as usual. This keeps a direct path the owner's companion
        // learned while parked working, without making this node general transit.
        uint8_t dest_hash = pkt->payload[0];
        uint8_t src_hash = pkt->payload[1];
        return (isOwnerHash(dest_hash) || isOwnerHash(src_hash)) ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_GRP_TXT:
      case PAYLOAD_TYPE_GRP_DATA: {
        if (pkt->payload_len < 1) return EDGE_DROP;
        return isChannel(pkt->payload[0]) ? EDGE_STOCK : EDGE_DROP;
      }
      case PAYLOAD_TYPE_ACK: {
        return _fwd_acks ? EDGE_STOCK : EDGE_DROP;
      }
      default:
        return EDGE_DROP;
    }
  }

  return EDGE_DROP;
}

// --- persistence: simple line-based text format ---
//   ER1
//   owner <64 hex chars of pubkey>
//   chan <2 hex chars of channel hash>
//   mirror_adverts 0|1
//   fwd_acks 0|1
// Any parse error invalidates the whole policy (fail closed).

static File openPolicyRead(FILESYSTEM* fs) {
#if defined(RP2040_PLATFORM)
  return fs->open(EDGE_POLICY_FILE, "r");
#else
  return fs->open(EDGE_POLICY_FILE);   // ESP32 default is read; NRF52 Adafruit default is FILE_O_READ
#endif
}

static File openPolicyWrite(FILESYSTEM* fs) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return fs->open(EDGE_POLICY_FILE, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(EDGE_POLICY_FILE, "w");
#else
  return fs->open(EDGE_POLICY_FILE, "w", true);
#endif
}

bool EdgePolicy::load(FILESYSTEM* fs) {
  _valid = false;
  _num_owners = 0;
  _num_channels = 0;
  _mirror_adverts = false;
  _fwd_acks = false;

  File f = openPolicyRead(fs);
  if (!f) return false;

  char line[80];
  int n = 0;
  bool got_magic = false;
  // parse one line at a time, char by char (f.read() is the portable primitive here)
  while (true) {
    int c = f.read();
    if (c < 0 || c == '\n') {
      line[n] = 0;
      // trim trailing CR/whitespace
      while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
      if (n > 0 && line[0] != '#') {
        if (!got_magic) {
          if (strcmp(line, "ER1") != 0) { f.close(); return false; }
          got_magic = true;
        } else if (memcmp(line, "owner ", 6) == 0) {
          uint8_t key[PUB_KEY_SIZE];
          if (strlen(line + 6) != PUB_KEY_SIZE * 2 || !mesh::Utils::fromHex(key, PUB_KEY_SIZE, line + 6)) {
            f.close(); return false;
          }
          if (addOwner(key) < 0) { f.close(); return false; }  // duplicate or full
        } else if (memcmp(line, "chan ", 5) == 0) {
          uint8_t h;
          if (strlen(line + 5) != 2 || !mesh::Utils::fromHex(&h, 1, line + 5)) {
            f.close(); return false;
          }
          if (addChannel(h) < 0) { f.close(); return false; }
        } else if (memcmp(line, "mirror_adverts ", 15) == 0) {
          _mirror_adverts = (line[15] == '1');
        } else if (memcmp(line, "fwd_acks ", 9) == 0) {
          _fwd_acks = (line[9] == '1');
        } else {
          f.close(); return false;  // unknown directive -> fail closed
        }
      }
      n = 0;
      if (c < 0) break;  // EOF
    } else if (n < (int) sizeof(line) - 1) {
      line[n++] = (char) c;
    }
    // lines longer than the buffer are truncated rather than aborting; the
    // truncated directive will simply fail to match and invalidate the file
  }
  f.close();
  if (!got_magic) return false;
  _valid = true;
  return true;
}

bool EdgePolicy::save(FILESYSTEM* fs) {
  File f = openPolicyWrite(fs);
  if (!f) return false;
  f.println("ER1");
  char hex[PUB_KEY_SIZE * 2 + 1];
  for (int i = 0; i < _num_owners; i++) {
    for (int k = 0; k < PUB_KEY_SIZE; k++) {
      sprintf(&hex[k * 2], "%02x", _owner_keys[i][k]);
    }
    f.print("owner ");
    f.println(hex);
  }
  for (int i = 0; i < _num_channels; i++) {
    sprintf(hex, "%02x", _channel_hashes[i]);
    f.print("chan ");
    f.println(hex);
  }
  f.print("mirror_adverts ");
  f.println(_mirror_adverts ? "1" : "0");
  f.print("fwd_acks ");
  f.println(_fwd_acks ? "1" : "0");
  f.close();
  _valid = true;
  return true;
}
