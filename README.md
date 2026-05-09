# Chat — End-to-End Encrypted Messenger with the Signal Protocol

A desktop chat application that implements **end-to-end encryption** following the
[Signal Protocol](https://signal.org/docs/) specification: **X3DH** (Extended
Triple Diffie–Hellman) for the asynchronous initial key agreement and the
**Double Ratchet** algorithm for the per-message symmetric ratchet.

The project is written in **Python**, ships with a **PySide6 (Qt)** graphical
client and an **aiohttp + python-socketio** relay server, and supports both
**text messages** and **encrypted file transfers**.

The server is a *dumb relay*: it stores nothing about the contents of the
conversation. All cryptographic operations — key generation, key agreement,
encryption, authentication, decryption — happen on the clients. The server
never holds, sees, or processes a single byte of plaintext.

> **What this README is.** A line-by-line walk-through of the cryptography in
> this repository, mapped against the official Signal specifications, written
> so a reader who has never seen Signal before can understand what each
> primitive does, *why* it is there, and *how* this implementation differs
> from the production protocol used by Signal Messenger and WhatsApp.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Repository Layout](#repository-layout)
4. [Requirements & Installation](#requirements--installation)
5. [How to Run the Application](#how-to-run-the-application)
6. [The Signal Protocol — Background](#the-signal-protocol--background)
7. [Cryptographic Primitives Used](#cryptographic-primitives-used)
8. [X3DH — Specification vs. This Implementation](#x3dh--specification-vs-this-implementation)
9. [The Double Ratchet — Specification vs. This Implementation](#the-double-ratchet--specification-vs-this-implementation)
10. [Symmetric Encryption Layer (AES-256-CBC + HMAC)](#symmetric-encryption-layer-aes-256-cbc--hmac)
11. [Wire Protocol — Socket.IO Events](#wire-protocol--socketio-events)
12. [Server Design](#server-design)
13. [Client / GUI Design](#client--gui-design)
14. [End-to-End Message Flow](#end-to-end-message-flow)
15. [Security Properties Achieved](#security-properties-achieved)
16. [Differences From the Official Signal Spec](#differences-from-the-official-signal-spec)
17. [Threat Model & What This Project Does *Not* Defend Against](#threat-model--what-this-project-does-not-defend-against)
18. [Known Limitations and Possible Improvements](#known-limitations-and-possible-improvements)
19. [Glossary](#glossary)
20. [Credits & References](#credits--references)

---

## Project Overview

This project is an academic re-implementation of the cryptographic core of
[Signal](https://signal.org/), the protocol behind **WhatsApp**, **Signal
Messenger**, **Facebook Messenger Secret Conversations**, **Skype Private
Conversations**, and many others.

The goal is **didactic**: to write each cryptographic primitive explicitly
(key agreement, KDF chain, ratchet step, AEAD construction, message header
serialization, skipped-key buffer) instead of relying on a high-level library
such as `libsignal`. That way, every line maps directly to a step in the
Signal specification and the reader can trace what is happening.

The result is a fully working messenger:

- two or more clients connect to a single relay server;
- the server **only forwards already-encrypted blobs** between clients;
- each pair of users derives an independent shared secret via X3DH;
- every message uses a **fresh symmetric key** thanks to the Double Ratchet;
- text messages **and arbitrary files** are end-to-end encrypted.

Why this matters in practice: an attacker who fully compromises the server
sees only base64-encoded ciphertexts and MAC tags. They cannot read past
messages, cannot inject new ones (any tampered ciphertext fails the
HMAC-SHA256 check), and cannot impersonate one user to another (every SPK
is signed with the owner's Ed25519 key and verified before X3DH proceeds).

---

## Features

- Username-based registration with an in-memory + TinyDB key directory.
- **Identity Key (IK)**, **Signed PreKey (SPK)** and **Ed25519 signing key
  (SIK)** generated on the client, never sent to the server in private form.
- SPK is signed with Ed25519; the receiver verifies the signature before
  starting X3DH — preventing a malicious server from substituting a fake
  prekey bundle.
- **X3DH** initial handshake (DH1 + DH2 + DH3 → HKDF-SHA256 → 32-byte SK).
- First X3DH-protected ciphertext that doubles as a *handshake confirmation*
  (`##CHAT_START##`). If decryption fails, the responder concludes that the
  initiator does not actually possess the matching `SK` and aborts.
- **Double Ratchet** with:
  - DH ratchet (X25519);
  - independent sending and receiving symmetric chains;
  - **out-of-order delivery** support via a skipped-message-keys buffer
    (`MKSKIPPED`, capped by `MAX_SKIP = 10`);
  - per-message header `(DH, PN, N)` so the receiver can locate the right
    chain key and derive the right message key.
- AEAD-style construction: **AES-256-CBC** + **HMAC-SHA256** in
  *Encrypt-then-MAC* mode, with key, MAC key and IV all derived from a single
  message key via HKDF.
- **Encrypted file transfer** reusing the same Double Ratchet session — the
  same security guarantees that protect chat text protect file payloads too.
- **PySide6** GUI: login, user list, per-peer chat window, file picker,
  out-of-order tolerant message rendering.
- **Socket.IO** transport for both client–server and (logical) peer-to-peer
  events.

---

## Repository Layout

```
Chat/
├── main.py                 # PySide6 Qt application: windows, screens, threads
├── requirements.txt        # Python dependencies
├── client/
│   ├── client.py           # Socket.IO client, User class, X3DH, dispatch
│   └── utils.py            # Crypto primitives: DH, HKDF, KDF_RK, KDF_CK,
│                           #   Header, RatchetEncrypt/Decrypt, AES+HMAC
└── server/
    ├── server.py           # aiohttp + python-socketio relay
    └── user_keys.json      # TinyDB file (public key directory)
```

`main.py` is the **entry point**. It is what you launch to use the app.
`client/` contains all the cryptography and the Socket.IO client logic.
`server/` is the relay server you must start once before any clients connect.

The split between `client/client.py` and `client/utils.py` is meaningful:

- `utils.py` contains **pure cryptographic functions** (no networking, no
  state outside the arguments that are passed in) — this is the part that
  maps almost one-to-one to the Signal spec.
- `client.py` contains the **stateful object** (`User`) that owns the
  long-term keys, the per-peer X3DH session, the per-peer Double Ratchet
  state, the local plaintext message log, and the Socket.IO callbacks.

---

## Requirements & Installation

### Prerequisites

- **Python 3.10+** (the typing `str | None` syntax in `server.py` requires
  3.10 or later).
- A working Qt platform (Linux/macOS/Windows). On headless Linux you will
  need an X server or Wayland session for the GUI.

### Install

```bash
git clone https://github.com/FrancescoGalazzo/Chat.git
cd Chat

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Main dependencies:

| Library | Role |
|---|---|
| `cryptography` | X25519, Ed25519, HKDF, HMAC, AES-CBC, PKCS#7 padding |
| `python-socketio` + `aiohttp` | Transport for client and server |
| `PySide6` | Qt GUI |
| `tinydb` | Lightweight JSON store for the public key directory |
| `pycryptodome` | (transitive — present in the environment) |

---

## How to Run the Application

The server listens on `http://localhost:8080`, which is also the address
hard-coded in `client/client.py` (`SERVER = 'http://localhost:8080'`).

### 1. Start the server

```bash
cd server
python server.py
```

The server **truncates** `user_keys.json` on startup
(`db.truncate()` in `server.py`), so each run begins with an empty directory.

### 2. Start one client per user (in another terminal)

```bash
python main.py
```

Type a username in the login screen. If the username is already used by an
online client, the GUI shows *"Username già in uso, scegline un altro."*
Otherwise the client is added to the directory and you land on the user list.

### 3. Chat

- Click another username on the *Select* screen → the client requests the
  peer's prekey bundle, runs **X3DH**, initialises the **Double Ratchet**, and
  opens the chat window.
- Type a message and click **Send** (encrypted text).
- Click **File** to pick any file and send it (encrypted attachment).
- **Back** returns to the user list; **Logout** disconnects.

---

## The Signal Protocol — Background

Before diving into code, here is the conceptual model the protocol is
solving for. Imagine Alice wants to send a private message to Bob, with
these constraints:

- **Bob may be offline** when Alice sends the first message.
- The **server must be untrusted** — it must not be able to read messages
  even if it is compromised, malicious, or under legal compulsion.
- The protocol must **survive long-term key compromise**: if an attacker
  steals Alice's identity key today, they should not be able to read the
  messages she sent last month.
- The protocol must **self-heal after a compromise**: even if an attacker
  steals the *current* session state, future messages must rapidly become
  unreadable to them again.
- **Reordering, duplication and message loss** are normal in real networks
  and the protocol must tolerate them.

The Signal Protocol is the canonical answer to this list. It is built from
two cryptographic protocols that run back-to-back:

1. **X3DH (Extended Triple Diffie–Hellman)** — establishes a shared secret
   `SK` between two parties even when one of them is *offline* at handshake
   time. This is achieved by publishing long-term and medium-term keys in a
   server-side *prekey bundle* and combining them with an ephemeral key on
   first contact. See the [X3DH specification](https://signal.org/docs/specifications/x3dh/).

2. **Double Ratchet** — once `SK` exists, each subsequent message uses a
   *fresh symmetric key* derived from a *root key* and *chain keys* that
   advance on every message and on every Diffie–Hellman ratchet step. See
   the [Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/).

Together they provide:

- **Forward Secrecy** — a compromise of long-term keys does not let an
  attacker decrypt past traffic. This works because chain keys only flow
  forward through HMAC and ephemeral DH outputs are deleted as soon as they
  are used.
- **Post-Compromise / Future Secrecy (Self-Healing)** — even if a session
  state leaks, future messages quickly become secure again thanks to the
  next DH ratchet step, which injects fresh entropy that the attacker did
  not see.
- **Asynchronicity** — Alice can send the first message even if Bob is
  offline. Bob's prekey bundle, fetched from the server, contains everything
  Alice needs to derive `SK` unilaterally.
- **Resilience to Out-of-Order delivery** — message keys are deterministic
  given the chain key and counter, so the receiver can compute the right
  key for a late message and store skipped keys for messages that have not
  arrived yet.
- **Authenticity** — every ciphertext is MAC'd, and the long-term identity
  keys are bound into the MAC's associated data, so an attacker cannot
  inject a message that decrypts under the recipient's view of the session.

---

## Cryptographic Primitives Used

This project relies on the [`cryptography`](https://cryptography.io/)
library and uses only standard, well-vetted primitives:

| Primitive | Purpose | Where in the code |
|---|---|---|
| **X25519** ECDH | All Diffie–Hellman exchanges (X3DH and DH ratchet) | `GENERATE_DH`, `DH`, `User.ik`, `User.spk`, `User.epk`, `state["DHs"]` |
| **Ed25519** | Signing the SPK so the receiver knows it is authentic | `User.sik`, `self.sik.sign`, `sik.verify` |
| **HKDF-SHA256** | Deriving the X3DH shared secret, root keys, encryption keys, MAC keys, and IVs | `KDF_RK`, `ENCRYPT_DOUB_RATCH`, `ENCRYPT_X3DH`, `receive_x3dh`, `perform_x3dh` |
| **HMAC-SHA256** | Symmetric chain step (`KDF_CK`) and message authentication | `KDF_CK`, `ENCRYPT_DOUB_RATCH`, `ENCRYPT_X3DH` |
| **AES-256 in CBC mode** | Bulk symmetric encryption of message and file bodies | `ENCRYPT_DOUB_RATCH`, `DECRYPT_DOUB_RATCH`, `ENCRYPT_X3DH`, `DECRYPT_X3DH` |
| **PKCS#7 padding** | Block-aligning plaintext for CBC | `padding.PKCS7(256).padder()` |

Notice: there is no use of *unauthenticated* AES — every ciphertext is
followed by an HMAC-SHA256 tag, and decryption verifies the tag *before*
returning plaintext. This is the **Encrypt-then-MAC** discipline.

---

## X3DH — Specification vs. This Implementation

X3DH solves the asynchronous first-contact problem: how can Alice and Bob
derive the same shared secret if Bob is offline when Alice initiates?

The answer is to have Bob *pre-publish* a "prekey bundle" of public keys,
some long-term and some medium-term, signed so they cannot be swapped by
the server. Alice picks up that bundle, generates an ephemeral key, and
combines all of those keys via several Diffie–Hellman exchanges.

### The official X3DH

In the canonical specification, every user publishes:

| Key | Type | Lifetime | Role |
|---|---|---|---|
| `IK` (Identity Key) | X25519 | long-term | Identifies the user, used for both DH and signing (via XEdDSA) |
| `SPK` (Signed PreKey) | X25519, signed by `IK` | medium-term, rotated | Provides forward secrecy for handshakes against an `IK` compromise |
| `SPK_sig` | XEdDSA / Ed25519 signature on the SPK | follows SPK | Lets the initiator verify the SPK belongs to the right `IK` |
| `OPK_i` (One-Time PreKeys) | X25519 | one-shot, server deletes after use | Maximum forward secrecy: each handshake consumes a different OPK |

Alice (initiator) requests Bob's bundle, generates an ephemeral
`EK_A`, and computes:

```
DH1 = DH(IK_A,  SPK_B)        # binds Alice's identity to Bob's medium-term key
DH2 = DH(EK_A,  IK_B)         # binds Alice's ephemeral to Bob's identity
DH3 = DH(EK_A,  SPK_B)        # binds the two non-identity keys together
DH4 = DH(EK_A,  OPK_B)        # only if a one-time prekey was used
SK  = HKDF(F || DH1 || DH2 || DH3 [|| DH4])
```

where `F = 0xFF * 32` (a curve-specific tag that prevents cross-protocol
attacks against ECDH on the same curve — Curve25519 outputs are 32 bytes
long, and prefixing with 0xFF×32 ensures the IKM cannot collide with raw
DH outputs from other contexts) and HKDF uses an all-zero salt of length
equal to the hash output (32 bytes for SHA-256).

**Why three (or four) DHs and not one?** Each DH binds together a different
combination of long-term, medium-term and ephemeral keys. The result is
that *all* of these private keys must leak for an attacker to recompute
`SK`. Furthermore, because `EK_A` is freshly generated and immediately
destroyed by Alice, even a future compromise of `IK_A` does not reveal old
session keys.

After deriving `SK`, both parties wipe the DH outputs and the ephemeral
keys from memory.

### What this project does

In `client/client.py` the same idea is implemented, but with two
significant simplifications and one minor structural change:

1. **The user's identity key (`ik`, X25519) and the *signing* key (`sik`,
   Ed25519) are separate.** Signal would normally use a single XEdDSA key
   for both, where the EdDSA private key is derived from the X25519 private
   key. Here the **SPK is signed with `sik`** (Ed25519) and verified by the
   receiver before the DH steps:

   ```python
   self.sik.sign(spk_bytes)                  # producer side
   sik.verify(spk_sig_bytes, spk_bytes)      # consumer side
   ```

   This is functionally equivalent for the security argument: the
   recipient can still authenticate the SPK as belonging to the claimed
   identity, the only difference is that the identity is now *two* public
   keys (an X25519 and an Ed25519) instead of one XEdDSA key. The trade-off
   is that there is more public material to pin per user; the upside is
   that the implementation is simpler and uses well-tested standard
   library primitives.

2. **No One-Time PreKeys are used (`DH4` is omitted).** This is allowed by
   the spec ("if no one-time prekey is available, the procedure runs
   without `DH4`") but it has security consequences: if Bob's `IK` *and*
   `SPK` are ever compromised at the same time, *every* X3DH handshake
   that ran with that `SPK` becomes reproducible by the attacker, because
   there is no per-handshake one-shot secret to protect them individually.
   With OPKs, even that double compromise leaks at most one handshake.

3. **The HKDF info string is a fixed ASCII tag** (`b"extended_triple_diffie_hellman"`)
   shared by both sides. The Signal spec leaves the info string up to the
   application; Signal Messenger uses one like `"WhisperText"`.

The three Diffie–Hellman exchanges performed by the **initiator**
(`perform_x3dh`):

```python
dh1 = self.ik.exchange(self.sessions[username]['spk'])    # IK_A · SPK_B
dh2 = self.epk.exchange(self.sessions[username]['ik'])    # EK_A · IK_B
dh3 = self.epk.exchange(self.sessions[username]['spk'])   # EK_A · SPK_B
```

The three on the **responder** side (`receive_x3dh`):

```python
dh1 = self.spk.exchange(ika)                              # SPK_B · IK_A
dh2 = self.ik.exchange(epk)                               # IK_B  · EK_A
dh3 = self.spk.exchange(epk)                              # SPK_B · EK_A
```

X25519 ECDH is *commutative* — `DH(a, B) == DH(b, A)` whenever `a, b` are
the private keys and `A, B` the public keys. That property is what makes
the two sides compute the same `dh1`, `dh2`, `dh3` even though the
arguments are flipped.

The shared secret is derived with **HKDF-SHA256**, salt `0x00 * 32`, info
`b"extended_triple_diffie_hellman"`, IKM `F || DH1 || DH2 || DH3` where
`F = 0xFF * 32`:

```python
hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
            salt=b"\x00"*32, info=b"extended_triple_diffie_hellman")
SK = hkdf.derive(b"\xff"*32 + dh1 + dh2 + dh3)
```

This matches the spec exactly **except** for the missing one-time prekey
contribution.

### Associated Data

After deriving `SK`, X3DH defines an **associated data** string used for
binding the handshake to specific identity keys. The reason is subtle but
important: without binding, an attacker who somehow tricks two users into
running X3DH with each other's keys swapped could obtain the same `SK`
without anyone noticing.

The spec defines:

```
AD = Encode(IK_A) || Encode(IK_B)
```

In this project `AD` is built as:

```python
ad = serialize(ik_bytes) + serialize(ik_b_bytes)   # base64 strings, concatenated
```

i.e. base64(IK_A) || base64(IK_B). The use of base64 instead of the raw
32-byte encoding is a project-specific choice (it makes the AD printable
and easier to log) and is harmless because the two sides apply the same
transformation. It is then used as the AD input of the authenticated
encryption that protects the first message.

### Handshake confirmation message

Once `SK` is derived, the initiator immediately sends a deterministic
plaintext (`##CHAT_START##`) encrypted with `SK` and bound to `AD` via
HMAC. The responder uses `DECRYPT_X3DH` to verify the MAC; if verification
fails the handshake is rejected:

```python
res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))
if not res[0]:
    print("DH Failed"); return False
```

This serves the same purpose as Signal's *encrypted initial message* — it
proves that the responder derived the same `SK` and that the AD (and hence
the identity keys) match. If an attacker had somehow tampered with the
prekey bundle in transit, the MAC of the handshake message would fail and
the responder would refuse to start the conversation.

---

## The Double Ratchet — Specification vs. This Implementation

After X3DH, both sides hold the same 32-byte `SK`. They use it to
initialize the Double Ratchet, implemented in `client/utils.py`:
`RatchetEncrypt`, `RatchetDecrypt`, `DHRatchet`, `KDF_RK`, `KDF_CK`,
`SkipMessageKeys`, `TrySkippedMessageKeys`.

The Double Ratchet is "double" because it has **two interlocking ratchets**:

- A **symmetric ratchet** (the chain key + KDF chain): every message
  advances the chain by one HMAC step, producing a fresh message key.
  Cheap, deterministic, lets both sides compute exactly the same key for
  message *n*.
- A **Diffie–Hellman ratchet**: every time one side sends with a new
  X25519 public key, both sides perform a DH and feed the output into the
  root key, then derive a new chain key. Expensive, non-deterministic in
  the sense that it depends on a freshly generated key, but it injects new
  entropy into the session.

The two ratchets together give *both* forward secrecy (the chain only goes
forward) *and* post-compromise security (every DH step heals from a leaked
state).

### Per-session state

Each direction stores the standard Double Ratchet state, exactly as in the
spec:

| Field | Meaning |
|---|---|
| `DHs` | own DH key pair (X25519) |
| `DHr` | peer's most recent DH public key |
| `RK` | root key |
| `CKs` | current sending chain key |
| `CKr` | current receiving chain key |
| `Ns` | sending message number (within current sending chain) |
| `Nr` | receiving message number (within current receiving chain) |
| `PN` | number of messages in the *previous* sending chain |
| `MKSKIPPED` | dictionary `(DHr, n) → mk` of out-of-order keys |

`PN` is what allows the receiver to know how many messages it might still
have to skip from the previous chain when the sender ratchets forward. If
Alice sent 5 messages on chain *X*, then ratcheted, then sends with chain
*Y* and stamps `PN = 5`, Bob knows that messages 0..4 of chain *X* may
still arrive late and stores skipped keys for them.

`MKSKIPPED` is the buffer of message keys for messages that have been
"skipped" — either because they are out-of-order, or because their chain
has been retired but they have not yet arrived. Each entry is indexed by
`(DH_public_key, message_number)`, which uniquely identifies a position in
the protocol's history.

Initialisation:

- The **initiator** (`init_ratchet_transmission`) generates a fresh `DHs`,
  takes the responder's `SPK_B` as its initial `DHr`, and immediately runs
  one `KDF_RK(SK, DH(DHs, DHr))` step to derive the very first `CKs`.
  This is exactly the spec's `RatchetInitAlice` procedure.
- The **responder** (`init_ratchet_receiver`) keeps its own `SPK_B` private
  key as `DHs`, sets `DHr = None`, `RK = SK`. It will produce its own `CKs`
  the first time the peer's DH key changes — i.e. when it processes the
  first inbound ratchet message from Alice and learns her new `DHs`.
  This is the spec's `RatchetInitBob` procedure.

This guarantees that the very first message Alice sends causes Bob's first
DH ratchet step, after which both sides have aligned chains.

### Sending: `RatchetEncrypt`

```python
def RatchetEncrypt(state, plaintext, AD):
    state["CKs"], mk = KDF_CK(state["CKs"])
    header = HEADER(state["DHs"], state["PN"], state["Ns"])
    state["Ns"] += 1
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header))
```

For every outgoing message the sender:

1. advances the **chain key** `CKs` and derives a fresh **message key** `mk`
   (via `KDF_CK`);
2. builds a header containing `(DHs.pub, PN, Ns)`;
3. encrypts the plaintext under `mk` with the AEAD construction
   (`ENCRYPT_DOUB_RATCH`), using `AD || header` as associated data;
4. increments `Ns`.

Critically, `mk` is **used exactly once** and then discarded; the next
message uses a different `mk` derived from the next chain key. Even if an
attacker gets `mk` for message 5, they cannot derive `mk` for message 4
(that key is already gone) nor for message 6 (the chain key for that step
has not been computed yet from the attacker's perspective).

### `KDF_CK` — symmetric chain step

Two HMAC-SHA256 evaluations from the same chain key with constant-byte
prefixes — exactly the construction recommended by the spec:

```
mk      = HMAC-SHA256(CK, 0x01)
next_CK = HMAC-SHA256(CK, 0x02)
```

The two distinct constants give domain separation between the message-key
derivation and the chain-advance derivation, ensuring that knowledge of
`mk` does not let you derive `next_CK` (and vice versa). The chain is
one-way: `CK → next_CK` is easy, `next_CK → CK` is computationally
infeasible.

### `KDF_RK` — root key step

`KDF_RK(rk, dh_out)` produces a new `(RK, CK)` pair using HKDF-SHA256,
output length 64:

```
HKDF(salt=rk, IKM=dh_out, info=b"kdf_rk_info") → (RK || CK)
```

The previous root key is used as **HKDF salt**, and the new DH output
(`dh_out`) is used as IKM. This is what causes the "self-healing" property:
once a fresh `dh_out` enters the construction (and that `dh_out` is the
output of an X25519 exchange the attacker has not seen), the new `RK`
becomes unpredictable to the attacker, even if they previously held the
old `RK`.

### Receiving: `RatchetDecrypt`

```python
def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext

    if x25519.X25519PublicKey.from_public_bytes(header.dh) != state["DHr"]:
        SkipMessageKeys(state, pn_int)
        DHRatchet(state, header)

    SkipMessageKeys(state, n_int)
    state["CKr"], mk = KDF_CK(state["CKr"])
    state["Nr"] += 1
    padded_plain = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    return PKCS7_unpad(padded_plain)
```

It implements the standard receive logic:

1. **Try the skipped-keys buffer first.** If the incoming `(DHr, n)` matches
   a previously-stored skipped key, pop it, decrypt and return. This handles
   out-of-order delivery — for example, if message 3 is delivered before
   message 2 was, message 2's key was stored when we computed past it, and
   we use it now.
2. **DH-ratchet check.** If `header.dh` is *new* (different from the `DHr`
   we currently have), the peer has performed a DH ratchet step. Skip every
   remaining message of the previous receiving chain
   (`SkipMessageKeys(state, pn)`), then call `DHRatchet`, which:
   - bumps `PN` (records how many messages we sent on the chain we are
     about to retire);
   - resets `Ns`, `Nr`;
   - sets `DHr = header.dh`;
   - derives the new receiving chain `(RK, CKr) ← KDF_RK(RK, DH(DHs, DHr))`;
   - generates a fresh local `DHs` and derives the new sending chain
     `(RK, CKs) ← KDF_RK(RK, DH(DHs, DHr))`.
3. Skip any keys before `header.n` (storing them in `MKSKIPPED`), then
   advance `CKr` once, derive `mk`, decrypt and unpad.

`MAX_SKIP = 10` caps the number of skipped keys retained between two
consecutive valid messages — a denial-of-service protection straight from
the spec (the canonical recommendation is 1000; this implementation chooses
a much tighter limit). The reason it matters: without a cap, a malicious
peer could send a message with `n = 2^32 - 1` and force the receiver to
compute and buffer 2^32 message keys.

### `DHRatchet` step in detail

```python
def DHRatchet(state, header):
    state["PN"] = state["Ns"]
    state["Ns"] = 0
    state["Nr"] = 0
    state["DHr"] = x25519.X25519PublicKey.from_public_bytes(header.dh)
    state["RK"], state["CKr"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
    state["DHs"] = GENERATE_DH()
    state["RK"], state["CKs"] = KDF_RK(state["RK"], DH(state["DHs"], state["DHr"]))
```

This is the heart of post-compromise security. Two HKDFs and two DHs are
performed: the first updates the *receiving* chain so we can decrypt the
incoming message and any siblings that follow; the second sets up the
*sending* chain for our next outbound message, using a brand new `DHs`
that the attacker cannot have. Once we send our first message under the
new `DHs`, the peer will perform its own `DHRatchet` and mirror us — and
the conversation has fully healed.

### Header serialization

`Header` is a small wrapper that base64-encodes its three fields:

```python
{ 'dh': base64(pk_bytes), 'pn': base64(pn_int_be), 'n': base64(n_int_be) }
```

so that it can travel inside a JSON Socket.IO payload. `pn` and `n` are
big-endian integer encodings of the counters (with a special `b"\x00"`
case for value 0 so the byte string is never empty).

---

## Symmetric Encryption Layer (AES-256-CBC + HMAC)

Both X3DH (`ENCRYPT_X3DH` / `DECRYPT_X3DH`) and the Double Ratchet body
(`ENCRYPT_DOUB_RATCH` / `DECRYPT_DOUB_RATCH`) use the **same Encrypt-then-MAC
construction**, which is the construction recommended by the Double Ratchet
specification when no native AEAD is available. Encrypt-then-MAC means the
MAC covers the *ciphertext* (and the AD), not the plaintext; the receiver
verifies the MAC *first*, and only decrypts if it passes — preventing
chosen-ciphertext attacks like padding oracles.

### Key derivation from `mk`

Given a 32-byte symmetric key `mk` (either `SK` for X3DH or the per-message
`mk` for the ratchet), HKDF-SHA256 expands it into 80 bytes:

```python
hkdf_out = HKDF(SHA256, length=80, salt=0x00*80, info=...).derive(mk)
enc_key  = hkdf_out[:32]      # AES-256 key
auth_key = hkdf_out[32:64]    # HMAC-SHA256 key
iv       = hkdf_out[64:80]    # 16-byte AES-CBC IV
```

The `info` string differs between the two contexts (`b"X3DH"` vs.
`b"encrypt_info_kdf"`), giving domain separation between handshake
encryption and ratchet encryption.

> **Note on the IV.** Deriving the IV from the message key (rather than
> using a per-message random IV) is acceptable here precisely because each
> `mk` is used exactly once, so the IV is never reused with the same key.
> This is the same construction Signal recommends for its "AES-CBC + HMAC"
> profile.

### Encryption

```
ciphertext = AES-256-CBC( enc_key, iv, PKCS7(plaintext) )
mac        = HMAC-SHA256( auth_key, PKCS7(AD) || ciphertext )
```

Notice that the **associated data is itself PKCS#7-padded** before being
fed into HMAC. This is a project-specific detail (HMAC has no need for
fixed-block input), but it is applied symmetrically on both encrypt and
decrypt and so is consistent. It is a deviation from the Signal
specification, which feeds the raw AD into the MAC.

### Decryption

```
verify HMAC-SHA256( auth_key, PKCS7(AD) || ciphertext ) == mac
plaintext = unpad( AES-256-CBC^{-1}( enc_key, iv, ciphertext ) )
```

If the MAC check fails, decryption is aborted (`Exception("MAC verification
failed")` for the ratchet, `(False, "")` for X3DH).

### What `AD` looks like for ratchet messages

`AD = ad_base64(IK_A) || ad_base64(IK_B) || header.dh || header.pn || header.n`

That is, the X3DH identity-key associated data is **bound into every single
message** by being concatenated with the per-message header inside the MAC.
This guarantees that a received ciphertext belongs to *this* X3DH session
and *this* ratchet position, and prevents an attacker from replaying a
ciphertext from a different session or different chain step.

---

## Wire Protocol — Socket.IO Events

Communication uses `python-socketio`. The following events are exchanged:

| Event | Direction | Purpose |
|---|---|---|
| `register_user` | C → S | Publish prekey bundle, claim a username |
| `user_joined` | S → C | Broadcast: a new user just registered |
| `user_left` | S → C | Broadcast: a user disconnected |
| `get_users` | C → S | Pull current online list |
| `request_prekey` | C → S | Fetch another user's prekey bundle |
| `x3dh_message` | C → S → C | Initiator sends EK + first ciphertext; relayed |
| `ratchet_msg` | C → S → C | Encrypted text message (ratcheted) |
| `file_msg` | C → S → C | Encrypted file (ratcheted) |
| `logout` | C → S | Voluntary disconnect |

All payloads use **base64-encoded byte strings** for keys, ciphertexts and
MACs so they can travel as JSON.

Example `ratchet_msg` payload:

```json
{
  "username": "<recipient>",
  "from":     "<sender>",
  "cipher":   "<base64>",
  "header":   { "dh": "<b64>", "pn": "<b64>", "n": "<b64>" },
  "hmac":     "<base64>"
}
```

Example `x3dh_message` payload:

```json
{
  "username": "<recipient>",
  "from":     "<initiator>",
  "ik":       "<base64 IK_A pub>",
  "epk":      "<base64 EK_A pub>",
  "cipher":   "<base64 of Enc(SK, '##CHAT_START##')>",
  "hmac":     "<base64 HMAC tag>"
}
```

---

## Server Design

`server/server.py` implements a minimal aiohttp + python-socketio relay:

- A single TinyDB file (`user_keys.json`) caches the public **prekey bundles**
  for online users; it is **truncated at startup**, so the directory is
  fully ephemeral.
- Two in-memory dictionaries map identities to live sockets:

  ```python
  user_map = {}   # username -> sid
  sid_map  = {}   # sid -> username
  ```

- `register_user` rejects duplicate usernames, stores the bundle,
  notifies everyone via `user_joined`, and replies with the current online
  list.
- `request_prekey` returns the public part of a peer's bundle.
- `x3dh_message`, `ratchet_msg` and `file_msg` are pure **forwarding
  events**: the server uses `sio.call(..., sid=user_map[recipient])` to push
  the encrypted blob to the recipient and return the recipient's
  acknowledgement back to the sender.
- `disconnect` removes the user from both maps and from TinyDB, then emits
  `user_left` to the rest.

The server has **no key material, no plaintext, no message log**. Even an
attacker with full server access only sees opaque ciphertexts, MACs and
public keys.

> **Why a relay instead of true peer-to-peer?** The whole point of X3DH is
> to support asynchronous communication: Alice posts her message *to a
> server* and Bob downloads it later. Even in this implementation, where
> Bob is required to be online for delivery, the relay topology is what
> would later let us add offline message storage without changing any of
> the cryptography.

---

## Client / GUI Design

`main.py` builds the GUI with **PySide6**:

- `LoginScreen` — username entry; on submit calls `User.register_user()`.
- `SelectScreen` — one button per online peer; clicking it triggers the
  X3DH bootstrap (`request_user_prekey_bundle` + `perform_x3dh`) and
  switches to the chat window.
- `ChatScreen` — text input, **Send**, **File**, **Back**; renders the
  per-peer message history (sent in green, received in red).
- `MainWindow` — wires Qt signals from the background `Worker` thread
  (`message_received`, `user_joined`, `user_left`, `file_received`) to the
  appropriate slots. The Socket.IO event loop runs in that worker thread to
  avoid blocking the Qt event loop.

`client/client.py` defines the `User` class — the actual cryptographic
state machine — plus `reg_callback`, which registers the Socket.IO event
handlers (`x3dh_message`, `ratchet_msg`, `file_msg`, `user_joined`,
`user_left`).

When a `user_left` event arrives, `cleanup_contact` wipes the local
`messages`, `x3dh_session`, `ratchet_session` and `sessions` entries for
that peer — a small but important hygiene step that bounds the lifetime of
plaintext history and ratchet state in memory.

---

## End-to-End Message Flow

A complete walk-through of *Alice* sending her first message to *Bob*:

1. **Both clients register.**
   Each generates `(IK, SIK, SPK)`, signs SPK with SIK, and pushes the
   bundle to the server with `register_user`.
2. **Alice picks Bob in the user list.**
   She fetches his bundle (`request_prekey`) and verifies `SPK_sig` with
   `SIK_B`. If verification fails, the entire handshake is aborted — a
   guarantee that no malicious server can substitute a bogus SPK.
3. **Alice runs X3DH (`perform_x3dh`).**
   She generates ephemeral `EK_A`, computes `dh1, dh2, dh3`, derives
   `SK = HKDF(0xFF*32 || dh1 || dh2 || dh3, info="extended_triple_diffie_hellman")`
   and forms `AD = b64(IK_A) || b64(IK_B)`. She immediately deletes
   `EK_A` and the three `dh*` outputs.
4. **Alice initialises her ratchet** as the *initiator*: fresh `DHs`,
   `DHr ← SPK_B`, first `(RK, CKs) ← KDF_RK(SK, DH(DHs, SPK_B))`.
5. **Alice sends the X3DH handshake message.**
   `ENCRYPT_X3DH(SK, "##CHAT_START##", AD)` produces `(ciphertext, mac)`.
   The payload `(IK_A, EK_A.pub, ciphertext, mac)` is forwarded via the
   server to Bob with the `x3dh_message` event.
6. **Bob receives `x3dh_message` (`receive_x3dh`).**
   He computes the *same* `dh1, dh2, dh3`, derives the *same* `SK`,
   verifies the MAC of the handshake ciphertext, and stores
   `(SK, SPK_B, AD)` in `x3dh_session`.
7. **Bob initialises his ratchet** as the *responder*: `DHs = SPK_B`,
   `RK = SK`, `DHr = None`. He has not derived any `CKs` yet — he only
   will when Alice (or he himself) performs a DH ratchet step.
8. **Alice sends a normal text message** with `RatchetEncrypt`:
   - new `mk` from `KDF_CK(CKs)`,
   - header `(DHs.pub, PN, Ns)`,
   - AES-256-CBC + HMAC over `AD || header || ciphertext`.
9. **Bob's `ratchet_msg` handler** calls `RatchetDecrypt`. Since
   `header.dh != DHr (None)` he runs `DHRatchet`, derives `CKr` (from his
   own `SPK_B`-as-`DHs` against Alice's new public key), then advances
   `CKr` once to obtain `mk`, verifies the MAC and decrypts.
10. From now on, every outgoing message advances the appropriate chain key
    (cheap), and any time one side answers with a fresh DH key the other
    performs a `DHRatchet` step (expensive but provides forward / future
    secrecy).

Files (`send_file` / `receive_file` / `decrypt_incoming_file`) follow the
*same* pipeline as text — they are simply larger plaintexts, encrypted
with the next message key from the same Double Ratchet, prefixed with the
filename in the JSON envelope.

---

## Security Properties Achieved

- **End-to-end encryption.** The server only sees `(ciphertext, mac, header)`
  blobs. There is no path inside `server.py` that touches plaintext.
- **Mutual authentication of public keys.** SPKs are verified via Ed25519
  before any DH step, so a malicious server cannot substitute fake prekey
  bundles.
- **Forward secrecy.** Compromising any single message key does not reveal
  past or future message keys: chain keys only flow *forward* through HMAC,
  and root-key updates use ephemeral X25519 outputs that are then erased.
- **Future / Post-Compromise Secrecy.** Each new DH ratchet step injects
  fresh entropy into the root key; once a healthy ratchet step happens, an
  attacker who briefly compromised state cannot follow the conversation.
- **Replay protection.** The MAC binds the message header `(DH, PN, N)` to
  the ciphertext, and the receiver only accepts each `(DH, N)` once because
  it consumes the corresponding `mk` (either from the chain or from
  `MKSKIPPED`).
- **Out-of-order tolerance.** Up to `MAX_SKIP = 10` messages can arrive out
  of order without breaking the session.
- **Domain separation.** Different `info=` strings keep handshake-encryption
  keys, ratchet-encryption keys, root-keys and chain-keys in separate KDF
  domains.
- **No cross-session replay.** AD always includes both parties' identity
  keys, so a ciphertext from session (Alice, Bob) cannot decrypt under
  session (Alice, Charlie).

---

## Differences From the Official Signal Spec

This implementation is **functionally faithful** to Signal but takes a few
shortcuts for clarity and didactic reasons. A direct table:

| Area | Official Signal | This project | Practical impact |
|---|---|---|---|
| Identity / signing key | One **XEdDSA** key — a single key used for both DH and EdDSA signatures | Two separate keys: `IK` (X25519, DH only) and `SIK` (Ed25519, signing only) | More public material per user; otherwise equivalent security. Must publish two keys instead of one. |
| One-Time PreKeys (`OPK_i`) | Yes — produces `DH4`; server replenishes them as they are consumed | **Not used** at all — `DH4` term omitted from `SK` derivation | If `IK_B` *and* `SPK_B` are both compromised, *every* X3DH that ran with that SPK can be reproduced. With OPKs, at most one handshake leaks per compromised OPK. |
| AEAD primitive | AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) | Same | None — matches the spec. |
| `MAX_SKIP` | Recommended ≈ 1000 | `10` | Larger windows of out-of-order delivery (more than 10 in a row) will break the session. |
| AD passed to MAC | Raw `AD ‖ header` | `PKCS7(AD ‖ header)` (extra padding step) | Harmless because it is symmetric, but a deviation from the spec; should be removed in a "spec-pure" version. |
| HKDF info strings | Application-defined, e.g. `"WhisperText"` | Hard-coded ASCII strings (`b"X3DH"`, `b"kdf_rk_info"`, `b"encrypt_info_kdf"`, `b"extended_triple_diffie_hellman"`) | None — purely a labelling difference, but the labels must match between peers. |
| Prekey storage | Pluggable backend; persists across server restarts | TinyDB JSON file, **truncated on startup** | Identities are wiped every time the server restarts; useful for testing, unsuitable for production. |
| SPK rotation | SPKs are rotated on a schedule (e.g. weekly), old SPKs retained briefly to decrypt in-flight handshakes | SPK is generated once at client startup and never rotated | If `SPK` private key is ever stolen, all future X3DH handshakes with that user are at risk until the user restarts. |
| Initial-message format | Defined precisely (PreKey message vs. normal message) and includes the OPK identifier | Custom: a single `x3dh_message` Socket.IO event, no OPK identifier | Cannot interoperate with libsignal. |
| Multi-device | Sender Keys / sealed sender / fan-out | Not implemented — one device per user | A user logged in on two clients with the same name conflicts on registration. |
| Sealed sender | Hides sender identity from the server | Not implemented — `from` field is plaintext on the wire | The server can see who is talking to whom (metadata leak). |
| Header encryption | Optional in spec ("HE" variant) — the header itself is encrypted | Not implemented — `(DH, PN, N)` are visible to the server | The server can see chain progression, which is a small additional metadata leak. |
| One-time prekey replenishment | Server requests fresh OPKs from the client when stock runs low | Not applicable | — |
| Bundle authenticity | Bundle is fetched over a TLS-pinned channel; the SPK signature is the only end-to-end check | SPK signature checked, but the bundle is fetched over plain HTTP/Socket.IO | A network attacker could observe (but not forge — signature still protects) the bundle. |
| AES IV | Per-message random IV or KDF-derived | KDF-derived from `mk` (matches spec) | None — equivalent. |
| Fingerprint / safety numbers | User-visible identity verification | Not implemented | Users cannot manually verify each other's identity keys. |
| Trust-on-first-use semantics | Yes, with explicit re-verification on key change | Implicit — there is no UI for key change detection | A server that maliciously substitutes the prekey bundle on the *very first* contact (before any prior trust exists) would still be detected by the SPK signature, but there is no warning if the bundle changes between sessions. |

---

## Threat Model & What This Project Does *Not* Defend Against

Being explicit about what is *out of scope* is as important as being clear
about what is in scope.

**Defended against:**

- A passive eavesdropper on the network (sees only ciphertext + public
  metadata).
- A malicious or compromised relay server that tries to read messages.
- A malicious server that tries to inject or modify messages (HMAC fails).
- A malicious server that tries to substitute a fake prekey bundle (SPK
  signature fails).
- Future compromise of a single message key (forward secrecy).
- Past compromise of session state (post-compromise / future secrecy after
  one DH ratchet step).
- Replay of a previously seen ciphertext within the same session.

**Not defended against:**

- A malicious server that performs a **MITM on the very first contact** by
  substituting *both* the user's `IK` *and* `SIK` *and* a self-signed SPK.
  Without an out-of-band identity check (a "safety number" UI like Signal
  Messenger has), there is no way for the user to detect this.
- **Endpoint compromise.** If the attacker has shell access to the user's
  machine, they can read plaintext directly from `User.messages`. There is
  no at-rest encryption of message history.
- **Traffic analysis / metadata.** The server sees who is talking to whom,
  when, and how big each ciphertext is. Sealed-sender and dummy traffic
  would mitigate this, neither is implemented.
- **Long-term key extraction.** Identity keys live in process memory; a
  memory-dumping attacker recovers them.
- **Denial of service.** A peer who sends garbage `header.dh` or
  out-of-order messages with `n > MAX_SKIP` can break the session.
- **Compromise of `IK_B` and `SPK_B` together** — without OPKs, this leaks
  all X3DH-derived `SK` for handshakes that used that SPK.

---

## Known Limitations and Possible Improvements

The list below is in roughly increasing order of effort. Each item refers
to a concrete deviation from the production Signal Protocol that could be
closed in this codebase.

### Cryptographic improvements

1. **Add One-Time PreKeys (OPKs).**
   - Generate a small pool of X25519 prekeys at registration time.
   - Publish them with the bundle; the server pops one per request and
     deletes it from the pool.
   - Include `DH4 = DH(EK_A, OPK_B)` in the IKM for `SK`.
   - Closes the *only* meaningful cryptographic gap with respect to the
     spec.

2. **Migrate to a unified XEdDSA identity key.**
   - Replace the separate `ik`/`sik` pair with a single identity key
     usable for both DH and EdDSA signing (XEdDSA / Ed25519 ↔ X25519
     interconversion).
   - Brings the prekey bundle closer in shape to libsignal's.

3. **Switch the AEAD to AES-256-GCM or ChaCha20-Poly1305.**
   - Single-pass, native AEAD primitives — replaces the manual
     Encrypt-then-MAC + HKDF-of-iv construction.
   - Removes the project-specific "PKCS7-padded AD" detail.
   - Reduces the chance of an implementation bug in the future.

4. **Increase `MAX_SKIP` to ~1000** (the Signal recommendation) and add a
   global cap on `MKSKIPPED` size to prevent unbounded memory use across
   many DH ratchet steps.

5. **Implement SPK rotation.**
   - Periodically (e.g. weekly) generate a new SPK, sign it with `SIK`,
     and re-publish the bundle.
   - Retain the previous SPK for some grace period so in-flight handshakes
     can still complete.

6. **Header encryption ("HE" variant).**
   - Encrypt `(DH, PN, N)` so the server cannot observe chain progression.
   - Adds a new symmetric chain dedicated to header keys.

7. **Sealed sender.**
   - Move the `from` field inside the encrypted envelope so the relay no
     longer learns which user sent which ciphertext.

8. **Constant-time comparisons everywhere.**
   - `sik.verify` and `h.verify` (from `cryptography`) are already constant
     time, but any future custom comparison should explicitly use
     `hmac.compare_digest`.

9. **Explicit memory zeroization.**
   - After deriving `SK`, the code deletes `dh1, dh2, dh3` with `del`,
     which is best-effort in Python. Using `bytearray` and overwriting the
     bytes is closer to the spec's "wipe" guidance.

### Protocol / persistence improvements

10. **Persistent identity.**
    - Save `IK`, `SIK`, `SPK` in an encrypted local key store (e.g.
      protected with a passphrase via Argon2id + AES-GCM) so that the user's
      identity survives restarts.
    - Stop truncating the server's TinyDB on startup.

11. **Trust on First Use + change detection.**
    - Cache each peer's `IK` (and `SIK`) on first contact.
    - On reconnection, compare against the cached value and warn the user
      if the keys have changed (the equivalent of Signal's "safety numbers
      changed" notification).

12. **Safety-number UI.**
    - Hash `(IK_A, IK_B)` into a short, human-readable fingerprint (numeric
      or QR-coded) so two users can verify identities out-of-band.

13. **Offline message queueing.**
    - When the recipient is offline, the server currently drops the
      message. A persistent encrypted queue would let X3DH be truly
      asynchronous.

14. **Configurable server endpoint.**
    - Currently `SERVER = 'http://localhost:8080'` is hard-coded.
    - Add a CLI flag / env var / GUI field for the address.

15. **TLS for the transport.**
    - Wrap Socket.IO in HTTPS/WSS so that even though application payloads
      are end-to-end encrypted, transport metadata (sizes, timing) is at
      least protected from passive eavesdroppers.

16. **Username authentication.**
    - Right now anyone can register any free username. A real deployment
      would tie usernames to long-term identity keys (e.g. proof of
      possession on registration) so that an attacker cannot squat a
      victim's name after they disconnect.

### Engineering improvements

17. **Unit tests.**
    - `pytest` cases for: `KDF_CK` determinism, `KDF_RK` determinism, full
      `RatchetEncrypt` ↔ `RatchetDecrypt` round-trip, out-of-order
      delivery, multiple DH ratchet steps, MAC failure, `MAX_SKIP`
      enforcement, X3DH with mismatched AD, X3DH with bad SPK signature.

18. **Integration tests with two simulated clients.**
    - Spin up server + two clients in `pytest-asyncio` and exercise the
      full happy path plus failure modes.

19. **File chunking and streaming.**
    - For now files are sent as a single Socket.IO event; large files
      block the event loop. Splitting files into ratcheted chunks gives
      better backpressure and progress reporting.

20. **GUI localisation.**
    - Strings are currently mixed Italian / English. Standardise on one
      and centralise translations.

21. **Logging hygiene.**
    - The current code prints raw cryptographic values (`print("recv:",
      plaintext)`). A production-style logger would never log plaintext or
      key material.

22. **Type hints + linting.**
    - Adopt full typing (`mypy --strict`) and a linter (`ruff`) so future
      contributors immediately see the shape of `state`, `header`, `data`
      dicts.

23. **Replace TinyDB with SQLite.**
    - TinyDB is fine for a demo but not for a multi-client scenario.
      SQLite (via aiosqlite) gives proper concurrency and persistence.

24. **CI workflow.**
    - GitHub Actions running tests, type-checking, and a linter on every
      push.

---

## Glossary

- **AD (Associated Data)** — Public, non-secret data that is bound into a
  MAC so that tampering with it (or replaying a ciphertext under a
  different context) causes verification to fail.
- **AEAD** — Authenticated Encryption with Associated Data: an encryption
  scheme that provides both confidentiality and authenticity, plus a
  mechanism to authenticate non-encrypted "associated data".
- **CK (Chain Key)** — A symmetric key used to derive a sequence of
  message keys via repeated HMAC.
- **DH (Diffie–Hellman)** — A key-agreement primitive; given two key
  pairs `(a, A)` and `(b, B)`, both sides can compute the same shared
  secret `DH(a, B) = DH(b, A)`.
- **EK / EPK (Ephemeral PreKey)** — A short-lived key generated by the
  initiator of an X3DH handshake; deleted immediately after `SK` is
  derived.
- **HKDF** — A standard KDF based on HMAC; given an input key and a
  context, it produces uniform pseudo-random output of the desired length.
- **IK (Identity Key)** — A user's long-lived public key, the anchor of
  their identity in the system.
- **MK (Message Key)** — A one-shot symmetric key used to encrypt and MAC
  exactly one message.
- **OPK (One-Time PreKey)** — A short-lived pre-published X25519 key
  consumed exactly once during X3DH; not used in this implementation.
- **PN (Previous Number)** — The number of messages the sender sent on
  their previous sending chain, before the most recent DH ratchet step.
- **RK (Root Key)** — The long-lived secret of the Double Ratchet, fed by
  every DH ratchet step.
- **SK (Shared Secret)** — The 32-byte secret produced by X3DH and used to
  initialize the Double Ratchet.
- **SPK (Signed PreKey)** — A medium-lived X25519 key signed by the
  user's identity (signing) key; published with the bundle.
- **X3DH** — Extended Triple Diffie–Hellman: the asynchronous handshake
  protocol; here "extended" means *more than one* DH per handshake.
- **XEdDSA** — A construction that lets a single Curve25519 key serve
  both as an X25519 key for ECDH and as an Ed25519-style signing key.

---

## Credits & References

- [Signal Protocol — X3DH specification](https://signal.org/docs/specifications/x3dh/)
  by Moxie Marlinspike and Trevor Perrin.
- [Signal Protocol — Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
  by Trevor Perrin and Moxie Marlinspike.
- [Signal Protocol — XEdDSA & VXEdDSA](https://signal.org/docs/specifications/xeddsa/)
  for the unified-identity-key construction this project simplifies.
- [pyca/cryptography](https://cryptography.io/) — primitives (X25519,
  Ed25519, HKDF, HMAC, AES-CBC, PKCS#7).
- [python-socketio](https://python-socketio.readthedocs.io/) — transport.
- [PySide6 / Qt for Python](https://doc.qt.io/qtforpython-6/) — GUI.
- [TinyDB](https://tinydb.readthedocs.io/) — JSON-backed key directory.

> **Author.** Francesco Galazzo — Master's degree in Computer Engineering
> (Cybersecurity), Politecnico di Torino.
> Implemented as a hands-on study of the Signal Protocol's cryptographic
> core. Pull requests, comments and review of the cryptographic choices are
> very welcome.
