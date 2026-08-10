// An honest passphrase hint.
//
// This grades LENGTH and shape. It does not know whether the passphrase is a common one,
// a name, or a keyboard walk, so it does not pretend to estimate how hard it is to guess.
// A meter that says "strong" about `Password123!` has taught the user something false, and
// the whole product is a bet that people believe what this app tells them.
//
// The number that matters is not here: the vault is wrapped with Argon2id at 256 MiB over
// 3 passes, which is what makes a stolen blob expensive to attack offline. The passphrase
// is what that cost is applied to.

export type PassphraseLevel = 'too-short' | 'short' | 'fair' | 'good';

export interface PassphraseHint {
  readonly level: PassphraseLevel;
  readonly label: string;
  readonly detail: string;
  /** False blocks creation. Unlock never consults this: an existing vault is what it is. */
  readonly acceptable: boolean;
}

/** Hard floor for a NEW vault. Not a guess at security, just a refusal to accept a token. */
export const MIN_PASSPHRASE_LENGTH = 12;

const ADVICE =
  'Several unrelated words are easier to remember and harder to search than one word with substitutions.';

export function passphraseHint(passphrase: string): PassphraseHint {
  // Code points, not UTF-16 units: an emoji or an accented character should count once.
  const length = [...passphrase].length;
  const words = passphrase.trim().split(/\s+/).filter(Boolean).length;

  if (length < MIN_PASSPHRASE_LENGTH) {
    return {
      level: 'too-short',
      label: `${length} of ${MIN_PASSPHRASE_LENGTH} characters`,
      detail: `Keyweave will not create a vault under ${MIN_PASSPHRASE_LENGTH} characters. ${ADVICE}`,
      acceptable: false,
    };
  }
  if (length < 20) {
    return {
      level: 'short',
      label: `${length} characters`,
      detail: `This is a length check, not a measure of how hard it is to guess. ${ADVICE}`,
      acceptable: true,
    };
  }
  if (words < 4) {
    return {
      level: 'fair',
      label: `${length} characters`,
      detail: `Long enough. This is a length check, not a measure of how hard it is to guess. ${ADVICE}`,
      acceptable: true,
    };
  }
  return {
    level: 'good',
    label: `${length} characters, ${words} words`,
    detail:
      'Long, and several words. This is still a length check: it cannot tell whether the words are a line from a song.',
    acceptable: true,
  };
}
