// Every string the ceremony can say that is not already sitting in index.html.
//
// The copy is part of the security, so it lives in one file the suite can read. Three
// rules it is held to, all enforced by tests:
//   - R1 is named in the product, not only in the docs. A compromised bundle can fake the
//     safety words; the person comparing them has to be told that before they compare.
//   - Nothing claims the relay cannot link two mailboxes. It can, by network address and
//     timing. That sentence was written once, was false, and was deleted; it does not come
//     back (residual R3).
//   - No claim words, no em dash (public-hygiene.test.ts).
//
// A refusal is written as three parts on purpose: what happened, what it means, and what
// to do instead. "Try again" is the wrong advice for every refusal in this file, and
// saying so plainly is the difference between a security control and a speed bump.

import type { FlushReport, ReceiveReport } from '../messaging.js';

export interface Refusal {
  readonly title: string;
  readonly detail: string;
  readonly advice: string;
}

export const REFUSAL_MISMATCH: Refusal = {
  title: 'Stopped: the words did not match',
  detail:
    'Different words on the two screens mean the two devices did not derive the same shared secret. Someone may be relaying between you, or one of the two codes came from a screen that is not in this room.',
  advice:
    'Nothing was saved and no contact was added. Do not retry this over a call, a photo or a screen share: that is the situation this check is designed to catch. Try again in person, on a different network, or on a different device.',
};

export const REFUSAL_PROOF: Refusal = {
  title: 'Stopped: they could not prove they hold the key',
  detail:
    'The other device sent a card and a signature that do not go together. A card is public and can be filmed or copied, so Keyweave also asks for a fresh signature; that is the part that failed.',
  advice:
    'Nothing was saved. This is what a replayed or photographed card looks like. Start over with the other person present and their device unlocked in front of you.',
};

export const REFUSAL_SELF: Refusal = {
  title: 'Stopped: that is your own card',
  detail: 'The code you scanned carries this device identity key.',
  advice: 'Point the camera at the other person screen, not at a mirror or your own second window.',
};

export const REFUSAL_ROLLBACK: Refusal = {
  title: 'Stopped: that card goes backwards',
  detail:
    'You have already pinned a newer card for this identity. A card with an older or equal serial that differs from the pinned one is a rollback, and Keyweave refuses it rather than quietly preferring one of the two.',
  advice:
    'Nothing was changed. Ask them which of their devices is current. Keyweave v0 has no way to revoke a key, so this has to be sorted out between the two of you.',
};

export const REFUSAL_BAD_CARD: Refusal = {
  title: 'Stopped: that card did not verify',
  detail:
    'The scanned card failed strict validation: signature, key encoding or key strength. Keyweave will not pin a key nobody can prove they hold.',
  advice:
    'Nothing was saved. If their screen is genuinely showing a Keyweave code, the bytes were altered between their screen and your camera.',
};

export const REFUSAL_CANCELLED: Refusal = {
  title: 'Pairing stopped',
  detail: 'You ended the ceremony before it finished.',
  advice: 'Nothing was saved and no contact was added.',
};

export const REFUSAL_INTERRUPTED: Refusal = {
  title: 'Stopped: the pairing could not continue',
  detail:
    'Something failed part way through this ceremony, so it was stopped rather than carried on from a half finished exchange.',
  advice:
    'Nothing was saved and no contact was added, and the camera has been released. Start over in person, with both devices unlocked and in front of you.',
};

export function interruptedRefusal(error: unknown): Refusal {
  const message = error instanceof Error ? error.message : String(error);
  return { ...REFUSAL_INTERRUPTED, detail: `${REFUSAL_INTERRUPTED.detail} (${message})` };
}

/**
 * What the screen says when the IDLE TIMER, not the person, ended the session. It is a
 * separate sentence from the storage failure below on purpose: telling somebody their
 * browser refused to write when in fact the app locked itself is the one kind of lie this
 * product cannot afford. The duration is passed in from the constant that governs it.
 *
 * TWO CLAUSES ARE NARROWER THAN THEY LOOK, and both were widened by mistake rather than on
 * purpose. This one string can appear on EVERY screen, because ui/app.ts onLock renders it
 * from a timer under whatever is up, so a sentence that is only true of the ceremony is a
 * false sentence on the conversation screen.
 *
 * "with nothing on this device reading the keys" replaced "with nothing happening". The
 * timer is rearmed by every unlocked READ of the vault (vault.ts assertUnlocked calls
 * touch()), not by the person being absent, so it can expire while the app is very much
 * busy: a refresh stalled on a slow relay touches nothing for the whole of its budget, and
 * that is exactly the window in which a conversation screen can reach this notice. Saying
 * "nothing happening" there told somebody the app had been idle while it was mid request.
 *
 * "Nothing was saved from it" replaced a bare "Nothing was saved", which is true of a
 * pairing and false of a conversation: an outbound message is sealed and written BEFORE the
 * relay is called (messaging.ts, order of writes on send), so a lock on that screen arrives
 * over a device that has saved things. The clause is now attached to the dropped pairing,
 * and the sentence after it says what does survive.
 *
 * "Messages you had already sent" replaced "Messages already sent or collected", because the
 * COLLECTED half was false on the one screen this notice most often appears over, and false
 * for the same reason the notice is showing at all. Inbound messages become durable at a
 * single persist() AFTER receive()'s loop, so a lock that lands mid pass loses everything
 * that pass had accepted (messaging.ts, and residual R18). Claiming they are still here, in
 * the very notice rendered when they are not, is the failure this whole change set exists to
 * remove. SENT is genuinely safe and stays: an outbound message is written before the relay
 * call. What was lost is named in R18 rather than in a sentence shown at every idle lock,
 * because the loss is the exception and a notice that cries wolf on every lock teaches
 * people to stop reading it.
 */
export function lockNotice(minutes: number): string {
  return (
    `Keyweave locked itself after ${minutes} minutes with nothing on this device reading the keys. ` +
    'The keys are out of memory and the passphrase is forgotten, so any pairing that was ' +
    'running has been dropped and the camera released. Nothing was saved from it. ' +
    'Messages you had already sent are still on this device. Unlock to carry on.'
  );
}

/**
 * What the UNLOCK screen says when opening or creating a vault failed.
 *
 * It is here rather than inlined at the call site because the call site used to render
 * `error.message` verbatim: whatever sentence the vault, the KDF worker or the browser's
 * storage layer happened to put in an Error went into the error slot AND into the live
 * region for a screen reader. A wrong passphrase is the most common failure in the whole
 * product, and what it showed was a developer's sentence about an AEAD.
 *
 * WHY THE WRONG-PASSPHRASE LINE DOES NOT SAY "wrong passphrase" AND STOP. The vault cannot
 * tell a wrong passphrase from an altered blob: both are one AEAD tag that did not verify.
 * Naming only the first would be a guess presented as a fact on a security product's most
 * used screen, and the second is the one worth knowing about. It says both, then says the
 * thing people actually need to hear once, which is that there is no reset.
 */
export const UNLOCK_COPY = {
  wrongPassphrase:
    'That passphrase did not open this vault. Either it is not the one the vault was created with, or the stored vault has been altered since it was written; this device cannot tell those apart. There is no reset and no recovery: the passphrase is the only way in.',
  noVault:
    'There is no Keyweave vault in this browser any more. Clearing site data removes it, and a private window never had one, and there is no copy anywhere else. This device has to create a new identity and pair again in person.',
  unknown:
    'Keyweave could not finish that, and the failure was not a refused passphrase, so nothing here says the passphrase is wrong. A private window or storage that is full are the usual causes.',
} as const;

/**
 * Which of the three the screen says, decided from the error the layer below threw.
 *
 * Matched on the OTHER file's own wording rather than on a guess, the same way
 * refusalForScanError is: `vault.ts` decryptVaultBlob throws 'vault: unlock failed (wrong
 * passphrase or tampered blob)', and `ui/session.ts` unlock throws 'session: no vault on
 * this device'. Anything else, including a storage layer that failed in its own way, gets
 * the line that claims nothing about the cause.
 */
export function unlockFailureMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes('unlock failed')) return UNLOCK_COPY.wrongPassphrase;
  if (message.includes('no vault on this device')) return UNLOCK_COPY.noVault;
  return UNLOCK_COPY.unknown;
}

export const REFUSAL_MAILBOX: Refusal = {
  title: 'Stopped: the drop box details did not verify',
  detail:
    'Along with their card, the other device sends the address of a drop box for your messages, signed with the same key. The signature did not match, which is what a second screen in the camera view looks like when it is trying to have your messages sent somewhere else.',
  advice:
    'Nothing was saved and no contact was added. Whoever did this could not have read the messages, but they could have kept them from arriving. Check that only their screen is in frame and start over.',
};

/**
 * Everything the scan step can throw, mapped to the refusal that names it. The mailbox case
 * can surface from EITHER the info payload or the card, because a coordinate that arrives
 * before its card is verified the moment the card lands, so both call sites route here.
 */
export function refusalForScanError(error: unknown): Refusal {
  const message = error instanceof Error ? error.message : String(error);
  // validate.ts and mailbox.ts are the authorities on these; match their own wording rather
  // than guessing at it.
  if (message.includes('equals our own')) return REFUSAL_SELF;
  if (message.includes('mailbox coordinate') || message.includes('mailbox:')) {
    return { ...REFUSAL_MAILBOX, detail: `${REFUSAL_MAILBOX.detail} (${message})` };
  }
  return { ...REFUSAL_BAD_CARD, detail: `${REFUSAL_BAD_CARD.detail} (${message})` };
}

export const SUPERSEDE_NOTICE =
  'This identity is already pinned with an older card. A key change requires a fresh in-person ceremony, which is exactly what you are doing now: if the words match, the new card replaces the old one.';

export const STEP_COPY = {
  showCard: {
    heading: 'Show this to their camera',
    lede: 'Hold the code steady and let them read it. It cycles through your contact card and a fresh random number for this ceremony, so give it a few seconds.',
  },
  showCardAndProof: {
    heading: 'Show this to their camera',
    lede: 'The code now also carries your signature for this ceremony. Same as before: hold it steady until they say they have it.',
  },
  showProof: {
    heading: 'One last code to show',
    lede: 'Your signature over this ceremony. They need it before their screen can show the words.',
  },
  scanPeer: {
    heading: 'Point your camera at their screen',
    lede: 'Keep the whole code in frame. Their screen cycles through more than one code, so stay on it until this screen moves on by itself.',
  },
  scanProof: {
    heading: 'One last code to read',
    lede: 'Their signature over this ceremony. Once it is in, both of you will see six words.',
  },
} as const;

export const CAMERA_COPY = {
  insecureContext:
    'This page is not on a secure origin, so the browser hides the camera entirely. That is a different failure from refusing permission: there is no prompt to accept. Open Keyweave over HTTPS, or on localhost.',
  denied:
    'The browser refused camera access for this page. Nothing was sent anywhere; the camera is used on this device only.',
  noCamera: 'No camera was found on this device.',
  inUse: 'The camera is busy. Another tab or application is holding it.',
  unknown: 'The camera could not be started.',
  refusedLiveChange:
    'This camera refused a live change to its settings. That is a camera quirk, not a failure: the stream is still running and decoding continues.',
} as const;

/**
 * Messaging copy. Two rules it is held to, both by tests:
 *   - nothing here says a message was DELIVERED. Delete-on-pull is at-most-once (R9) and v0
 *     has no acknowledgement, so "the relay took it" is the last true thing this device
 *     knows. Saying more would be the same kind of lie as a fake safety word.
 *   - nothing here says the relay learns nothing. It sees which mailbox is written and read,
 *     when, from which network address, and how big each message is (R3).
 */
export const CONVERSATION_COPY = {
  empty: 'No messages yet. Anything you send is sealed on this device before it leaves it.',
  notPinned:
    'This identity is not pinned on this device, so there is nothing to send to. Pair in person first.',
  noMailbox:
    'This pairing has no drop boxes. One of the two devices could not reserve one while you were pairing, so there is nowhere to put a message. Pair again in person, with both devices online, to connect it.',
  queued: 'Queued on this device',
  relayed: 'Handed to the relay',
  // The vault emptied itself part way through a refresh or a send. It is here rather than
  // left to fall through to the developer string because describeMessagingFailure's last
  // line returns error.message, so a MessagingError state with no entry in this object is
  // an internal sentence rendered on screen and read out to a screen reader. It says what
  // stopped, never that anything was lost: an id that was not pulled is still at the relay,
  // which is what the lock check in messaging.ts receive() is for.
  locked:
    'Keyweave locked itself while that was running, so it stopped there. Nothing was collected from the relay after the lock. Unlock and refresh to pick up anything waiting.',
  // The sentence that stops "Sent" from being read as "Delivered".
  deliveryNote:
    'Handed to the relay means the relay accepted the bytes. Keyweave has no way to see whether the other device has collected them, because the relay deletes a message the moment it is collected and sends back no receipt.',
  metadataNote:
    'The relay that carries your messages sees which mailbox is written and read, when, from which network address, and how many bytes each message is. It cannot open any of them.',
  forwardSecrecyNote:
    'This version seals with long term keys. If one of those keys is taken from a device later, the messages already sent can be read with it.',
  // Bytes, not characters, and the difference is worth a clause: accented and non-Latin
  // text costs two to four bytes per character, so a message can be well under any
  // character count a person would guess and still be over this. Saying only "4096 bytes"
  // to someone writing Japanese reads as the app refusing their language at random.
  tooLong: (limit: number) =>
    `A message is at most ${limit} bytes. Characters outside the Latin alphabet cost ` +
    `several bytes each, so shorten it and send again.`,
} as const;

/**
 * What to say about a relay failure. Never blames the peer, because the relay is the liar.
 *
 * THE 'timeout' LINE HAS A PRECONDITION and it is not decorative: "nothing was lost" is true
 * of a request that could not have destroyed anything, which is every request here EXCEPT a
 * pull that was in flight and never came back with an answer. The relay deletes a blob
 * before it writes the bytes, so a pull that ended in a timeout may have taken the message
 * with it, while a pull the relay REFUSED (401, 429) was decided before its delete and took
 * nothing. messaging.ts draws that line and counts the undecidable side
 * (ReceiveReport.interrupted), which gets interruptedPullMessage below. Anything printing
 * this line for a receive has to check that count first, or it is telling somebody their
 * message is safe at the one moment it is not.
 */
export function relayFailureMessage(failure: string): string {
  switch (failure) {
    case 'timeout':
      return 'The relay did not answer in time. Nothing was lost; try again in a moment.';
    case 'network':
      return 'The relay could not be reached, or it answered from somewhere else and Keyweave refused to follow.';
    case 'unauthorized':
      return 'The relay refused the drop box credentials for this pairing. The box may have been reclaimed after a long silence, which needs a fresh pairing in person.';
    case 'rate-limited':
      return 'The relay is rate limiting this device. Wait a little before asking it again.';
    case 'not-found':
      return 'The relay says this drop box is not there.';
    case 'too-large':
      return 'The relay refused the message for being too large.';
    case 'full':
      return 'The relay has no room. This is a capacity problem at the relay, not a problem with the message.';
    case 'oversize':
      return 'The relay sent back more data than a message can be, so the answer was dropped unread.';
    case 'malformed':
      return 'The relay sent back something that is not what the protocol says it should be, so it was dropped unread.';
    default:
      return 'The relay answered with an error.';
  }
}

/**
 * What to say when a refresh ended with a pull still in flight (ReceiveReport.interrupted).
 *
 * This is the one failure in the app where the truthful sentence is not reassuring. The
 * relay removes a blob before it sends it, so a pull that did not finish may have destroyed
 * the message, and this device cannot tell which happened. The alternative wording, the
 * generic "nothing was lost", is worse than blunt: it is the sentence a person reads at the
 * moment of failure, so it becomes their account of what the product did, and it talks them
 * out of the only step that recovers the message. So it says what is uncertain, says it in
 * one clause, and ends on the action.
 *
 * It does not name a count of messages, because there is at most one: a pull that fails
 * stops the pass. It does not name a CAUSE either, and that is deliberate rather than vague:
 * the count covers a deadline that fired, a connection that died, and a relay that broke
 * mid-request (messaging.ts counts a 5xx here because the relay's own catch-all wraps its
 * delete), and this device cannot tell which of those destroyed anything. Naming one of them
 * would be a detail the code does not have. The statuses the relay DECIDES before it deletes
 * (401, 429) are not in the count, so this sentence never appears under them.
 */
export function interruptedPullMessage(): string {
  return (
    'A message was being collected when the transfer failed. ' +
    'The relay deletes a message as it hands it over, so that one may be gone: ' +
    'ask your contact to send it again.'
  );
}

/**
 * WHAT ONE REFRESH DID, in counts a person can check against what they see on the screen.
 *
 * It lives in the copy file rather than in app.ts because it is pure string building and
 * app.ts is not importable without a DOM, so the only wall this could be given there was a
 * regex over its own source. A source regex is not a wall: flipping one character of the
 * guard below left that test green. Every rule this function carries is decidable by calling
 * it, so ui-shell.test.ts calls it and asserts the rendered sentences.
 *
 * THE RULE IT EXISTS FOR. relayFailureMessage('timeout') ends on "Nothing was lost", which
 * is true of a request that could not have destroyed anything and false of a pull that was
 * in flight and never answered, because the relay deletes a blob before it sends it. So when the
 * RECEIVE half reports an interrupted pull, its timeout line is dropped and the blunt
 * sentence takes its place: two accounts of one event, one of them reassuring, is worse than
 * the blunt one alone, and the reassurance is the one a person acts on.
 *
 * IT IS DROPPED FOR THE PHASE THAT PRODUCED IT, NEVER FOR THE OTHER ONE. A flush that timed
 * out left its record queued with its bytes, to be offered again on the next pass, so
 * "nothing was lost" is a true thing to say about the send half and it stands even when the
 * receive half lost something. The two sentences that result are about two different halves
 * of one refresh, not two accounts of one event, and the specific one ends on the action.
 *
 * THE PARTS ARE SENTENCES. Each is stripped of a trailing stop before the separator is
 * added and the whole line is terminated once: the counts carry no stop and the copy
 * sentences do, and joining the two kinds with '. ' is where "refused to follow.. A message
 * was being collected" came from.
 */
export function syncSummary(result: { flush: FlushReport; receive: ReceiveReport }): string {
  const parts: string[] = [];
  if (result.flush.relayed > 0) parts.push(`${result.flush.relayed} handed to the relay`);
  if (result.flush.queued > 0) parts.push(`${result.flush.queued} still queued here`);
  parts.push(
    result.receive.accepted === 1 ? '1 new message' : `${result.receive.accepted} new messages`,
  );
  // Listed by the relay and never asked for, because the pass ran out of its budget. Said
  // out loud: a silent shortfall is how a slow relay looks like an empty mailbox.
  if (result.receive.unread > 0) parts.push(`${result.receive.unread} still waiting at the relay`);
  const failure = result.flush.failure ?? result.receive.failure;
  const lost = result.receive.interrupted > 0;
  // Which half the failure came from, decided the same way the line above picked it.
  const fromReceive = result.flush.failure === undefined;
  if (failure && !(lost && fromReceive && failure.failure === 'timeout')) {
    parts.push(relayFailureMessage(failure.failure));
  }
  if (lost) parts.push(interruptedPullMessage());
  return `${parts.map(withoutTrailingStop).join('. ')}.`;
}

function withoutTrailingStop(part: string): string {
  return part.endsWith('.') ? part.slice(0, -1) : part;
}

/** A scanned symbol that is not one of ours is ordinary noise, never an attack signal. */
export function scanCounters(malformed: number, capped: number): string {
  const parts: string[] = [];
  if (malformed > 0) {
    parts.push(`${malformed} other code${malformed === 1 ? '' : 's'} in view, ignored`);
  }
  if (capped > 0) {
    parts.push(`${capped} Keyweave frame${capped === 1 ? '' : 's'} refused for being out of bounds`);
  }
  return parts.join('. ');
}
