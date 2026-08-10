# Keyweave

Meet once with light, then talk over the open internet with certainty about who
you are talking to.

Keyweave is a secure messenger with an unusual trust model. Two people pair **in
person** by pointing one phone's camera at another phone's screen, which streams a
signed contact card as an animated QR code (embedding the fountain-coded optical
transport from [decimen-optical-transfer](https://github.com/bashalarmistalt/decimen-optical-transfer)).
Because a camera pointed at a screen cannot be intercepted from the network,
**physical presence is the authentication** - this is the part every other
end-to-end-encrypted system struggles with (Signal's safety numbers, PGP's web of
trust). After pairing, messages travel over ordinary clearnet as sealed ciphertext
through a dumb mailbox relay that only ever sees ciphertext and an opaque routing
tag.

## What Keyweave protects, and what it does not

Keyweave aims to be honest about its limits. In plain terms:

- **Protects:** an in-person-authenticated identity (the relay never learns your
  identity keys), message confidentiality and integrity against the relay and the
  network.
- **Does not protect (v0):** the integrity of the code your browser is served (this
  is web software; see the delivery/trust notes), traffic metadata (an observer of
  the relay can see which mailboxes talk to each other by timing and network
  address), forward secrecy (a later key compromise can decrypt past messages), or a
  compromised/stolen unlocked device.

The threat model, named residuals, and the full protocol are in `docs/`.

## Status

Early development. v0 is deliberately small: optical pairing (SAS-with-DH
verification) + static-key sealed-box messaging + a pull-model mailbox relay, text
only. No forward secrecy, groups, or multi-device yet.

Built so far: the crypto core, the mailbox relay, the optical transport, and the
browser app, including the pairing ceremony and one-to-one text messaging over the
relay. Nothing is deployed.

The browser UI HAS been run in a browser, which this file previously denied. A full
three-turn ceremony ran on two physical devices on 2026-08-09, and the three arms that
remained after it, the mismatch refusal, camera denial and the insecure-context control,
ran headlessly against a real virtual camera on 2026-08-10. What no test here has done is
light two screens at the same time in front of two people; that is what R15 still names.

## Layout

- `client/` - the browser client (TypeScript): key management, contact cards,
  pairing crypto, message sealing, the encrypted local vault, and the pairing app in
  `client/src/ui/`.
- `relay/` - the store-and-forward mailbox relay (Python, standard library).
- `docs/` - architecture, protocol, threat model, named residuals, the hardened
  design spec, and the deploy CSP.

## Running the client

```sh
cd client
npm install
npm run dev        # loopback only, 127.0.0.1:5173
npm run build      # emits dist/
npm run gate       # typecheck plus the whole suite
```

The camera needs a secure context, so pairing works on `localhost` or over HTTPS and
nowhere else. There is no CI runner in this repository: `npm test` run by whoever
touches the code is what "enforced" means, and it includes the build-time assertion
that no external origin survives in `dist/`.

## License

MIT (see `LICENSE`). Third-party attributions in `NOTICE`.
