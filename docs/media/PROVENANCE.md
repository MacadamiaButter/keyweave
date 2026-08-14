# Media provenance: the pairing images

The files beside this one are captures of the Keyweave client running. Not one of them is a
mock-up, a drawing, or a screen with content injected into it: every screen was reached by
driving the real app, and the words and keys visible in them were derived by real
cryptography from identities created for the capture and thrown away afterwards.

A screenshot of a security product is a claim like any other, so this file records what was
real in each capture and what was standing in for something real. There are two sets.

## The 2026-08-13 set

`keyweave-unlock.png`, `keyweave-show.png`, `keyweave-scan.png`, `keyweave-pairing.gif` and
`keyweave-pairing-still.png`, recorded by driving one headless browser through the app.

**Real:** the shipped client, built from the sources in this repository with `npm run build`;
key derivation and a passphrase-sealed vault doing their actual work; and a relay process the
app really called, because reaching the show screen reserves a drop box at the relay, which
is R19. Those sources are the ones the signed `v0.1.2` tag carries: every entry under
`client/` matches that tag except `client/test`, which does not enter the bundle. The build
was the same-origin configuration, the one `scripts/reproduce.sh` produces with
`KEYWEAVE_SAME_ORIGIN=1`, so these bytes are not the bytes the public app serves. The sources
behind them are.

**Synthetic:** one machine, one browser, no second device and no person. The passphrase and
the identity were invented for the capture. The viewport is pinned to 430 by 820 at twice
that device pixel ratio rather than photographed off a phone. In `keyweave-scan.png` the
green pattern inside the camera frame is the browser's own synthetic test device, which is
what a headless capture has instead of a lens; the counter and the frame-rate note beside it
are the app reading that device, and they are real readings of a fake camera.

The animation was sampled 96 times in 9.57 seconds. The number of modules on the canvas was
read at every sample and ran 37, 41, 37, 41: three stream switches and 96 distinct codes,
which is how the recording is known to be the app's own animation and not a loop artifact.

## The 2026-08-10 set

`keyweave-compare.png`, `keyweave-paired.png` and `keyweave-refused.png`, from a real pairing
ceremony run as release evidence.

**Real:** Keyweave instances that had never met, real cryptography, real codes carried
optically from one screen into another's camera, and six safety words each side derived from
the key material it actually received. In the successful run the two sides' compare captures
are byte-identical to each other, which is that run's finding. In the refusal run a third
real instance sat between the two sides and paired with each of them as itself, which is why
those two screens showed different words: `keyweave-refused.png` is that attempt being
caught, not a screen posed to look like it.

**Synthetic:** browser instances on one machine rather than two people with two phones, and a
virtual camera device in place of a lens pointed across a table. Nobody said the words out
loud, and the buttons were pressed by the harness. R15 in
[../NAMED-RESIDUALS.md](../NAMED-RESIDUALS.md) is exactly that gap, and it stays open.

## The files

| File | What it shows | Captured | Pixels | Bytes | sha256 begins |
|---|---|---|---|---|---|
| `keyweave-pairing.gif` | The pairing code as it plays: 96 codes in 9.6 seconds, three switches between the two streams the app alternates | 2026-08-13 | 512x512, 96 frames | 923,980 | `f0465a77d57ccdd6` |
| `keyweave-pairing-still.png` | One frame of that animation, for a reader or a browser that asks for reduced motion | 2026-08-13 | 512x512 | 6,332 | `2f5ca65a95df7952` |
| `keyweave-unlock.png` | First run: the screen that generates the two keys and wraps them with a passphrase | 2026-08-13 | 860x1640 | 149,540 | `9eb053dc478e5c44` |
| `keyweave-show.png` | Turn 1 of 3, showing the code to the other camera, one frame of it held still | 2026-08-13 | 860x1610 | 116,024 | `a8ab4892fbeb192d` |
| `keyweave-scan.png` | Turn 2 of 3, watching the other screen and counting the codes read so far | 2026-08-13 | 860x1640 | 142,339 | `ccf9f575829ea5d5` |
| `keyweave-compare.png` | Turn 3 of 3: the six words both screens derived, and the two buttons that settle it | 2026-08-10 | 485x789 | 76,401 | `913ddb5c5ad85591` |
| `keyweave-paired.png` | After both sides agreed the words matched: the pinned key and its card serial | 2026-08-10 | 500x789 | 55,947 | `fa5eefbcb816ce17` |
| `keyweave-refused.png` | The mismatch: nothing saved, no contact added, start over in person | 2026-08-10 | 500x789 | 53,706 | `1fab42127cf88a29` |

The digests are the first 16 characters of each file's sha256, which is enough to tell a file
apart from a different one. To check a file here against this table:

```sh
sha256sum docs/media/keyweave-pairing.gif
```

## Notes

- The 2026-08-13 stills are whole viewport shots. `keyweave-show.png` has its bottom 30
  pixels trimmed, where the shot cut a status line in half. The 2026-08-10 stills are at
  their native size and are not upscaled. Anything displaying these has to size them itself.
- `keyweave-compare.png` is the one file altered after capture: a 15 pixel column of browser
  scrollbar was cut off its right edge, which is why it is 485 wide where its two companions
  are 500. Every remaining pixel is the evidence file's.
- `keyweave-pairing-still.png` is frame 55 of `keyweave-pairing.gif`, byte for byte, rather
  than a separate render, so the still cannot drift from the animation it stands in for.
- The animation was written with a palette of 16 colours and no dithering. It is cropped to
  the code itself, and every edge of that crop was checked to be white, so it carries none of
  the page behind it and reads correctly on a light page or a dark one.
- There is no conversation screenshot here. Recreating one needs the virtual camera rig
  again, so it is deferred rather than faked.
