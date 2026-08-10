// Sending and receiving over the untrusted relay. No DOM, no fetch: it is handed a
// RelayClient and a narrow view of the unlocked vault, so the suite can drive it against a
// relay stub that lies in every way the wire allows.
//
// WHAT THE RELAY CAN DO TO THIS CODE, and what happens: it can reorder (the replay window
// plus seen-set is order-insensitive by design, and the view sorts by the sender's own
// timestamp), duplicate (the authenticated msg-id dedupes), drop (nothing is lost that was
// not already at-most-once), replay old blobs (the window hard-rejects below it and the
// seen-set covers inside it), return a blob nobody sent or one addressed to somebody else
// or one from another sender (all three fail the AEAD or the inner identity checks in
// seal.ts open()), return a truncated or byte-flipped blob (AEAD), return ten thousand blob
// ids (the batch is capped), and hang (every request carries a deadline).
//
// NONE OF THAT IS SHOWN TO THE USER AS SOMETHING THEIR CONTACT DID. A blob that will not
// open is relay noise: the relay, not the peer, is the likely author, and a screen that
// says "your contact sent an invalid message" is a screen that teaches people to distrust
// each other on the word of the one component nobody trusts. The counts are kept for
// diagnostics and the conversation simply does not contain them.
//
// THE WP1 CALLER OBLIGATION, which is the load-bearing one here. An admit that is not saved
// is gone at lock, and an in-window replay of an unsaved admit IS accepted again after
// reopen (vault.ts lock() says so in as many words). So receive() persists before it
// returns, in the same call that admitted, and the suite pins it: admit, save, reopen, and
// the same message now dedupes.
//
// ORDER OF WRITES ON SEND. The outbox entry is persisted BEFORE the relay is called, never
// after. A crash between the two costs a duplicate delivery, which the peer's replay guard
// eats; the other order costs a message that was accepted by the relay and forgotten here.

import { sha512 } from '@noble/hashes/sha2.js';
import { concatBytes, toHex, utf8 } from './bytes.js';
import { open, seal } from './seal.js';
import { toRelayMailboxId } from './mailbox.js';
import { RelayError, type RelayClient } from './relay-client.js';
import type { ContactCard } from './card.js';
import type { KeyManager } from './keys.js';
import type { ReplayGuard } from './replay.js';
import type { MailboxPairing, MessageRecord } from './vault.js';

/**
 * A text messenger, so the cap is generous for prose and small next to the relay's 64 KiB
 * blob ceiling. Blob SIZE is visible to the relay (residual R3), which is the other reason
 * not to make this large.
 */
export const MAX_BODY_BYTES = 4096;

/**
 * Pulls attempted in one receive(). The relay chooses how many ids to list, so without a cap
 * it chooses how much work this device does. Well above the relay's own per-mailbox blob cap
 * of 100 is pointless; a smaller number just means the rest arrive on the next refresh.
 */
export const MAX_PULLS_PER_RECEIVE = 32;

/**
 * WALL-CLOCK CEILING ON ONE receive() PASS, shared across every request it makes.
 *
 * MAX_PULLS_PER_RECEIVE bounds the COUNT of relay-chosen work units and nothing bounded
 * their COST: a relay that lists 32 blobs and then paces the bytes of each one to just
 * inside the per-request deadline spends 32 deadlines inside a single call. The caller
 * holds a screen still for the whole of it (ui/app.ts disables the composer while a sync
 * runs), so the relay, not the person, would be choosing when a message can be written.
 *
 * The budget is spent, not merely checked between pulls: what is left of it is handed to
 * each request as a shortened deadline, so the pass costs one budget in total. Whatever is
 * still listed when it runs out stays in the mailbox and arrives on the next refresh, which
 * is why a small number is safe here. One poll interval (ui/app.ts POLL_INTERVAL_MS) is the
 * unit that matters: the pass should be over by the time the next one is due, and it is
 * equal to this, so a pass that spends the whole budget lands exactly on it. The one path
 * that can go slightly past (see MIN_PULL_DEADLINE_MS, at most half a pull floor) costs a
 * single skipped refresh and nothing else, because the poll and the buttons share one busy
 * flag: a poll that fires during a sync returns without doing anything.
 *
 * THE LIST DOES NOT GET ALL OF IT. MIN_PULL_DEADLINE_MS is held back from the list's own
 * deadline so that a list which answers at all has left enough behind to pull with. See
 * that constant for why the reservation has to happen before the list rather than after it.
 *
 * MEASURED ON A MONOTONIC CLOCK, never on the wall clock. NTP and cellular time sync step
 * `Date.now()` on the phones this is written for, and a budget measured with it inherits
 * both directions of that: a step BACKWARDS inflates every later reading of what is left,
 * so the ceiling silently stops applying and the relay gets the screen for as long as it
 * likes, which is the one thing this constant exists to prevent; a step FORWARDS spends the
 * budget without any work being done. `performance.now()` is unaffected by either. The
 * ACCEPTANCE WINDOW is a different quantity and stays on the wall clock: it is compared
 * against a sender's authenticated timestamp, so it has to mean the same thing on both
 * devices, which a per-process monotonic reading does not.
 */
export const RECEIVE_BUDGET_MS = 20_000;

/**
 * MINIMUM DEADLINE A PULL MAY BE STARTED WITH. Below this the pull is not attempted at all.
 *
 * A pull is NOT a retryable read. The relay deletes the blob inside the critical section
 * BEFORE the bytes reach the wire (relay/keyweave_relay.py pull_blob), so a request that is
 * aborted after the connection is established but before the body completes destroys the
 * message: the relay has dropped it, this client never parsed it, and the sender cannot
 * resend because flush() has already marked the record relayed and discarded its wire bytes.
 *
 * Spending the budget down to its last millisecond therefore turns the tail of every pass
 * into a hole. It is not a hostile-relay problem: an honest relay over a slow link is the
 * ordinary case that hits it, and the budget was added to defend against a hostile one.
 * Below the floor the id is simply left unpulled, which is safe by the same delete-on-pull
 * rule that makes a truncated pull unsafe: a blob never asked for is still in the mailbox.
 *
 * THE FLOOR IS RESERVED, NOT MERELY CHECKED, and that is the difference between a rule and
 * a wish. Checked against whatever the list happens to leave behind, it makes the first
 * pull depend on how long the list took, and a list slow enough to spend the budget leaves
 * a mailbox that nothing can ever empty: every pass lists the same ids, refuses to pull any
 * of them, and an honest relay on a slow link becomes a permanently empty inbox. That is
 * the failure this constant exists to prevent, arrived at from the other direction. So
 * receive() shortens the LIST's deadline by this value, and the constructor caps this value
 * at half the budget so neither phase can starve the other.
 *
 * WHAT THE PAIR BUYS, STATED AS THE SUITE PINS IT AND NOT ONE WORD WIDER. Every pull that is
 * STARTED is given a deadline of at least this floor, on every branch below. That is the
 * invariant; it is about the DEADLINE, not about what is left of the budget, because the
 * exempt first pull may be handed the floor when less than the floor remains (the bounded
 * overrun RECEIVE_BUDGET_MS names). And a list that answers with ids has at least one of
 * them pulled UNLESS the list overran its own deadline far enough to eat the reservation,
 * which is the case the paragraph below is about: 'a budget that is genuinely spent refuses
 * even the reserved first pull' pins listed=1 with zero pulls at the transport, which is
 * this rule's deliberate exception and not a hole in it.
 *
 * THE RESERVATION CAN STILL BE EATEN, which is why receive() checks rather than assumes. A
 * list that overruns its own deadline (a frozen tab, a suspended machine, an event loop
 * that came back late) hands back control with less than the floor left, and in the worst
 * case with the whole budget gone. The exemption receive() grants the first pull is
 * therefore bounded: it holds only while at least HALF the reservation survives, so the
 * pass can overrun by at most half of this value, and a budget that is genuinely spent
 * refuses the pull outright. Refusing costs one poll interval and destroys nothing, because
 * an id never asked for is still in the mailbox; attempting on a spent budget starts a pull
 * with the bare minimum on a link that has just proved it is slower than that, and under
 * delete-on-pull the message that pull aborts is gone for good. The asymmetry is what
 * decides it.
 *
 * IT IS ALSO CAPPED TO THE RELAY CLIENT'S OWN PER-REQUEST DEADLINE. That deadline is a
 * ceiling on every request (relay-client.ts `limitMs`), so a floor above it is a promise
 * the transport cannot keep: every pull would run shorter than the floor while this comment
 * claimed otherwise, and ids would be refused for budget that could never have been spent
 * on them. The constructor takes the smaller of the two instead, which makes the sentence
 * above true rather than merely intended.
 */
export const MIN_PULL_DEADLINE_MS = 3_000;

/**
 * WALL-CLOCK CEILING ON ONE flush() PASS, shared across every push it makes.
 *
 * The same argument as RECEIVE_BUDGET_MS, about the same screen: ui/app.ts disables the
 * composer for the WHOLE sync, and a sync is flush and then receive. Bounded only by the
 * per-request deadline, the send half costs one deadline PER QUEUED RECORD it gets through.
 *
 * WHICH RELAY DOES THAT, measured rather than assumed, because the obvious guess is wrong: a
 * relay that accepts the connection and then says nothing costs ONE deadline, not one per
 * record, since the first failure ends the pass. The shape that spends the queue is a relay
 * that ANSWERS every push, each one just slowly enough, which keeps the loop going and buys
 * a deadline per entry. How deep the queue is is not the relay's choice; the cost of each
 * entry in it is, and that is enough to hand the relay the screen. The whole pass costs this
 * instead: what is left of it is handed to each push as a shortened deadline, so a relay
 * that says nothing costs the budget rather than the transport's ceiling, and whatever is
 * still queued when it runs out is offered again on the next refresh.
 *
 * NO FLOOR, AND THE ASYMMETRY IS WHY THERE IS NONE. A pull destroys what it abandons: the
 * relay deletes the blob before the bytes reach the wire, so a pull started with a sliver of
 * budget is a message gone for good, which is the whole of MIN_PULL_DEADLINE_MS. A push
 * abandons nothing: the record keeps `delivery: 'queued'` and its wire bytes, the next pass
 * offers it again, and the worst case is a delivery the relay had already accepted arriving
 * twice, which the peer's replay guard eats. So the send half needs a budget and none of the
 * floor machinery, and the first offer of a pass is always made whatever the clock says.
 *
 * ONE REQUEST DEADLINE, deliberately, and the suite pins the relation rather than the
 * number: the ordinary send is a single put, so under the shipped defaults that put is
 * handed exactly what it is handed with no budget at all (relay-client's
 * DEFAULT_TIMEOUT_MS), and a queue of any depth costs that in TOTAL rather than that much
 * per record. A sync therefore costs at most this plus RECEIVE_BUDGET_MS plus the bounded
 * overrun named there, which is what docs/NAMED-RESIDUALS.md publishes.
 */
export const FLUSH_BUDGET_MS = 15_000;

/** Domain label for the LOCAL key on an outbound record. Never compared to an inbound id. */
const CTX_OUTBOX_ID = utf8('keyweave-outbox-id-v1');

/** What messaging needs from the unlocked session, and nothing else (anchor `leastpriv`). */
export interface MessagingHost {
  keys(): KeyManager;
  replay(): ReplayGuard;
  /**
   * Whether the vault has emptied itself since this pass began. Every other method here
   * THROWS once that has happened, which is too late for a pull: the relay deletes a blob
   * before the bytes reach the wire, so a pull issued into a locked vault destroys the
   * message and then fails to open it. This is the one question receive() has to be able to
   * ask WITHOUT touching the vault, so an implementation must not rearm the idle timer
   * answering it (Vault.isLocked reads a field and does not call touch()).
   */
  isLocked(): boolean;
  /** The pinned card for a peer, or undefined when that identity is not pinned. */
  cardFor(peerId: Uint8Array): ContactCard | undefined;
  mailboxFor(peerId: Uint8Array): MailboxPairing | undefined;
  /** The live record array. Mutating it is only durable once persist() resolves. */
  messages(): MessageRecord[];
  /** Snapshot, seal and write. Resolves only once the write has landed. */
  persist(): Promise<void>;
}

export type MessagingState = 'ready' | 'not-pinned' | 'no-mailbox';

/**
 * Why a send or receive could not even be attempted, or could not be finished. Distinct
 * from a relay failure.
 *
 * 'locked' is the one state that is not about the peer or the message: the vault emptied
 * itself part way through a pass. It is a THROW rather than a field on the report because
 * the caller has to be able to tell it apart from a pass that merely collected nothing:
 * ui/app.ts keeps a `locked` flag precisely so it can stop repainting a screen whose vault
 * has no keys in it, and a report that resolves never reaches that flag.
 */
export class MessagingError extends Error {
  constructor(
    readonly state: Exclude<MessagingState, 'ready'> | 'too-long' | 'empty' | 'locked',
    message: string,
  ) {
    super(message);
    this.name = 'MessagingError';
  }
}

export interface FlushReport {
  /** Entries the relay accepted in this pass. */
  relayed: number;
  /** Entries still queued afterwards, whether or not this pass tried them. */
  queued: number;
  /**
   * Queued entries carrying no wire bytes, so they can never be offered. Counted rather
   * than relabelled: they stay queued, which is the truthful state, and they are included
   * in `queued` above. Always 0 on a vault this app wrote.
   */
  stuck: number;
  /** The failure that stopped the pass, if one did. */
  failure: RelayError | undefined;
}

export interface ReceiveReport {
  /** Blob ids the relay listed, after validation and de-duplication. */
  listed: number;
  /** Blobs pulled and opened and admitted. These are the ones now in the conversation. */
  accepted: number;
  /** Pulled, but the relay said it was gone by the time we asked. */
  vanished: number;
  /** Would not open: tampered, not for us, not from this peer, or never a message at all. */
  unopenable: number;
  /** Opened and authentic, but the replay guard had seen it already. */
  duplicate: number;
  /** Opened and authentic, but dated below the acceptance window. */
  stale: number;
  /** Per-blob transport defects: a body past the ceiling, or a response of the wrong shape. */
  defective: number;
  /** Listed but not asked for, because the pass ran out of its budget. */
  unread: number;
  /**
   * PULLS THAT WERE STARTED AND NEVER DECIDED: the request went out and came back as a
   * transport failure rather than as an answer. Under delete-on-pull these may already be
   * destroyed, because the relay removes the blob before the bytes reach the wire and this
   * client cannot see how far the request got. It is the count the UI needs to avoid
   * telling someone nothing was lost when something may have been, and the only recovery is
   * for the sender to send it again.
   *
   * WHAT COUNTS IS WHETHER THE FAILURE COULD HAVE LANDED AFTER THE DELETE. A transport
   * failure could: no answer ever came back, so the request may have got as far as the
   * relay's critical section or nowhere near it. A STATUS the relay chose to send could not,
   * for the statuses the shipped relay sends on a pull: `_route_get` runs `_authz` first and
   * `store.pull_blob` (the only deleter) after it, so a 401 or a 429 is decided before
   * anything is removed and the blob is still there on the next refresh. Counting those was
   * telling somebody to ask their contact to send it again in the same breath as "the relay
   * is rate limiting this device", about a message the relay had not touched. A 5xx is
   * counted, because the relay's own last-ditch handler (`_guarded`) wraps the whole route
   * INCLUDING the delete, so that one genuinely cannot be told apart.
   *
   * A hostile relay can of course delete a blob and then answer 429. It gains nothing by it:
   * 404 destroys the same message with no warning at all (`vanished`), so the count would
   * not have caught a liar and did cost a false alarm on the ordinary path. `vanished` (a
   * 404, which is an ANSWER and lets the pass carry on) is not counted, because that id was
   * already gone before we asked. `defective` is not counted either: those pulls DID
   * complete, and their own wording never claims anything survived.
   *
   * 0 or 1 in practice, since a pull that fails stops the pass. A count rather than a flag
   * because every other field here is one, and because the reason it cannot exceed 1 is a
   * property of the loop below rather than of this interface.
   */
  interrupted: number;
  /** The transport failure that stopped the pass, if one did. */
  failure: RelayError | undefined;
}

export interface MessagingOptions {
  /** Wall-clock ceiling on one receive() pass. Defaults to RECEIVE_BUDGET_MS. */
  receiveBudgetMs?: number;
  /** Smallest deadline a pull may be started with. Defaults to MIN_PULL_DEADLINE_MS. */
  minPullDeadlineMs?: number;
  /** Wall-clock ceiling on one flush() pass. Defaults to FLUSH_BUDGET_MS. */
  flushBudgetMs?: number;
}

export class Messaging {
  private readonly receiveBudgetMs: number;
  private readonly minPullDeadlineMs: number;
  private readonly flushBudgetMs: number;

  constructor(
    private readonly host: MessagingHost,
    private readonly relay: RelayClient,
    options: MessagingOptions = {},
  ) {
    this.receiveBudgetMs = msOption(options.receiveBudgetMs, RECEIVE_BUDGET_MS);
    // TWO CAPS, and both of them make a claim elsewhere in this file true rather than
    // hopeful. HALF THE BUDGET is the constructor's half of the reservation fix (the other
    // half is in receive()): clamping the floor to the WHOLE budget was not enough, because
    // the budget is sampled again after the list returns, so a floor equal to the budget
    // refuses the first pull as soon as a millisecond has passed, which is to say almost
    // always. Half is the split that leaves neither phase able to starve the other. THE
    // RELAY CLIENT'S PER-REQUEST DEADLINE is the second: it bounds every request, so a floor
    // above it is a deadline no pull can be given. Both are caps rather than values, so the
    // shipped pair (3s inside 20s, under a 15s request deadline) is untouched by either.
    // The 1ms result under the caps is reachable from any budget of 3ms or less, which no
    // caller has and which could not hold two requests whatever this were set to.
    this.minPullDeadlineMs = Math.min(
      msOption(options.minPullDeadlineMs, MIN_PULL_DEADLINE_MS),
      Math.max(1, Math.floor(this.receiveBudgetMs / 2)),
      // THROUGH THE SAME DOOR AS THE OPTIONS, because it is one: RelayClient takes its
      // timeoutMs from a caller too and does not check it either, so `new
      // RelayClient({timeoutMs: NaN})` reaches this line as NaN, and one NaN in a Math.min
      // is a NaN floor, which loses every comparison in receive() and silently removes the
      // pull floor entirely. msOption is the argument in the file already: make the shape
      // unrepresentable rather than trust every future caller. A non-finite ceiling says
      // nothing about what the transport can honour, so it falls back to the budget, which
      // leaves this cap inert and the other two deciding. Every finite value behaves exactly
      // as the bare Math.max did.
      msOption(relay.requestCeilingMs, this.receiveBudgetMs),
    );
    this.flushBudgetMs = msOption(options.flushBudgetMs, FLUSH_BUDGET_MS);
  }

  /** Whether this peer can be messaged at all, and if not, which thing is missing. */
  state(peerId: Uint8Array): MessagingState {
    if (!this.host.cardFor(peerId)) return 'not-pinned';
    if (!this.host.mailboxFor(peerId)) return 'no-mailbox';
    return 'ready';
  }

  /**
   * The conversation with one peer, oldest first. Sorted by the SENDER's timestamp, which is
   * the only ordering both devices agree on; arrival order is the relay's to choose and is
   * therefore not a fact about the conversation. Ties break on the record's local id so the
   * order is stable across renders.
   */
  conversation(peerId: Uint8Array): MessageRecord[] {
    const key = toHex(peerId);
    return this.host
      .messages()
      .filter((m) => toHex(m.peerId) === key)
      .sort((a, b) => a.timestampMs - b.timestampMs || compareIds(a, b));
  }

  /**
   * Seal one message, record it as queued, PERSIST, and only then offer it to the relay.
   * Resolves once the send has been attempted; the returned report says whether the relay
   * took it. "Taken by the relay" is not "delivered" and the UI is held to that distinction.
   */
  async send(peerId: Uint8Array, text: string, nowMs: number = Date.now()): Promise<FlushReport> {
    const { card } = this.require(peerId);
    const body = utf8(text);
    if (body.length === 0) throw new MessagingError('empty', 'messaging: nothing to send');
    if (body.length > MAX_BODY_BYTES) {
      throw new MessagingError(
        'too-long',
        `messaging: a message is at most ${MAX_BODY_BYTES} bytes, this one is ${body.length}`,
      );
    }
    const wire = await seal(this.host.keys(), card, body, { timestampMs: nowMs });
    this.host.messages().push({
      peerId: Uint8Array.from(peerId),
      direction: 'out',
      timestampMs: nowMs,
      body,
      msgId: outboxId(wire),
      delivery: 'queued',
      wire,
    });
    // Durable BEFORE the network call. See the header note on the order of writes.
    await this.host.persist();
    return this.flush(peerId);
  }

  /**
   * Offer every queued outbound message to the relay, oldest first, stopping at the first
   * failure so the peer sees them in the order they were written. R9 is why the entry
   * survives the attempt: delete-on-pull is at-most-once, so an unacknowledged message is
   * kept and re-offered rather than assumed gone.
   *
   * BOUNDED BY ONE BUDGET, like receive() and for the same reason: the composer is disabled
   * for the whole sync, so a pass that costs one per-request deadline for every record it
   * gets through lets the relay decide when a person may write. See FLUSH_BUDGET_MS for
   * which relay actually does that, and for why this half needs no floor. Whatever is still
   * queued when the budget runs out is offered again on the next refresh, which costs
   * nothing: the record and its wire bytes are still here.
   */
  async flush(peerId: Uint8Array): Promise<FlushReport> {
    const { mailbox } = this.require(peerId);
    const key = toHex(peerId);
    const pending = this.host
      .messages()
      .filter((m) => toHex(m.peerId) === key && m.direction === 'out' && m.delivery === 'queued')
      .sort((a, b) => a.timestampMs - b.timestampMs || compareIds(a, b));

    // Monotonic, for the reason RECEIVE_BUDGET_MS gives: a wall clock stepped backwards by a
    // time sync inflates every reading of what is left, and a budget that can be inflated is
    // not a ceiling.
    const elapsedSince = monotonicClock();
    const startedAt = elapsedSince();
    const remainingMs = () => this.flushBudgetMs - (elapsedSince() - startedAt);

    let relayed = 0;
    let stuck = 0;
    let offered = 0;
    let failure: RelayError | undefined;
    for (const record of pending) {
      if (!record.wire) {
        // A queued entry with no bytes cannot be re-offered and cannot be reconstructed
        // without minting a second message. Leave it QUEUED and skip it: 'relayed' is the
        // one value that would be a lie, because it prints "Handed to the relay" under the
        // bubble for a message the relay never saw, and a false delivery claim through
        // state is no better than one through copy. Skipping cannot loop, since flush walks
        // a snapshot once per call. Unreachable from application code today (send() always
        // sets wire, and wire is deleted only after a 201), so this is the shape a future
        // caller or a hand-edited vault meets, not a live path.
        stuck++;
        continue;
      }
      const left = remainingMs();
      // THE BUDGET, CHECKED ONLY AFTER THE FIRST OFFER. The first record of a pass is always
      // offered: the clock is sampled at the top of this function with nothing but local
      // array work in between, so a short reading here means the machine stopped, and a pass
      // that refuses every record on a stopped clock is an outbox that never drains. There is
      // no floor beyond that because there is nothing to protect: a push that is abandoned
      // leaves the record queued with its bytes, so the cost of getting a short deadline is
      // one wasted request, not a destroyed message. That is the whole difference from the
      // pull side (FLUSH_BUDGET_MS, MIN_PULL_DEADLINE_MS).
      //
      // THE FAILURE IT REPORTS IS 'timeout', the same one receive() synthesises when its own
      // budget runs out, and it is a deliberate reuse rather than a precise cause: the relay
      // may have answered everything it was asked and simply not been asked again. What
      // makes the screen honest here is the count beside it, `queued`, which says how many
      // are still on this device; the reassurance the timeout line carries ("nothing was
      // lost") is true of this path, which is the part that must not be wrong.
      if (offered > 0 && left <= 0) {
        failure = new RelayError(
          'timeout',
          'relay: the pass ran out of time before every queued message was offered',
        );
        break;
      }
      offered++;
      try {
        await this.relay.putBlob(
          toRelayMailboxId(mailbox.outboxId),
          mailbox.outboxWriteCap,
          record.wire,
          Math.max(1, left),
        );
      } catch (error) {
        failure = asRelayError(error);
        break;
      }
      record.delivery = 'relayed';
      delete record.wire;
      relayed++;
    }
    if (relayed > 0) await this.host.persist();
    const queued = this.host
      .messages()
      .filter((m) => toHex(m.peerId) === key && m.direction === 'out' && m.delivery === 'queued')
      .length;
    return { relayed, queued, stuck, failure };
  }

  /**
   * List, pull, open, admit, persist. Every per-blob failure is counted and skipped; only a
   * transport failure stops the pass, because a relay that has stopped answering will not
   * answer the next pull either.
   *
   * The whole pass runs under ONE elapsed-time budget (RECEIVE_BUDGET_MS), spent across the
   * list and every pull. A per-request deadline alone bounds one answer; it does not bound
   * a relay that lists many blobs and paces each answer to just inside that deadline, and
   * the count cap does not either. Anything still listed when the budget runs out is left
   * where it is: nothing was pulled, so nothing was deleted, and the next refresh asks
   * again.
   *
   * TWO CLOCKS, ON PURPOSE. The budget is measured with the MONOTONIC clock, which no time
   * sync can step (see RECEIVE_BUDGET_MS). The caller's `nowMs` is the ACCEPTANCE WINDOW
   * time, is wall clock by definition because it is compared against a sender's
   * authenticated timestamp, and is a fixture in the suite. Neither is ever used for the
   * other, and mixing them is how a clock step turns into either an unbounded pass or a
   * destroyed message.
   *
   * The budget is SPLIT rather than raced for: the pull floor is subtracted from the list's
   * deadline up front, so the two phases cannot starve each other. Both halves of that are
   * load-bearing and both are argued at the point of use below.
   */
  async receive(peerId: Uint8Array, nowMs: number = Date.now()): Promise<ReceiveReport> {
    const { card, mailbox } = this.require(peerId);
    const mailboxId = toRelayMailboxId(mailbox.inboxId);
    // Resolved once per pass so every reading in it comes from the same clock, even in a
    // runtime where the monotonic one only appears later.
    const elapsedSince = monotonicClock();
    const startedAt = elapsedSince();
    const remainingMs = () => this.receiveBudgetMs - (elapsedSince() - startedAt);
    const report: ReceiveReport = {
      listed: 0,
      accepted: 0,
      vanished: 0,
      unopenable: 0,
      duplicate: 0,
      stale: 0,
      defective: 0,
      unread: 0,
      interrupted: 0,
      failure: undefined,
    };

    let summaries;
    try {
      // RESERVE THE FLOOR BEFORE ASKING, never after. remainingMs() is sampled again once
      // this call returns, so handing the list the whole budget made the first pull depend
      // on whether the clock happened to tick during it: any list at all leaves less than
      // the budget behind, and a floor measured against the budget then refuses the pull.
      // Shortened by the floor instead, a list that RESPECTS ITS DEADLINE leaves the floor
      // behind, and a list too slow to fit fails as a list timeout, which destroys nothing
      // because listing does not delete.
      //
      // "Respects its deadline" is the qualification, and it is not pedantry: the deadline
      // is enforced by a timer in the relay client, on the same event loop, so a frozen tab,
      // a suspended machine or a late timer can hand control back here with the whole budget
      // gone and the reservation gone with it. The suite has that case ('a budget that is
      // genuinely spent refuses even the reserved first pull' returns a 200 list with the
      // budget overrun by a full second), which is exactly why the loop below CHECKS what is
      // left instead of assuming the reservation survived. On the ordinary path the pass
      // costs one budget; the one bounded exception is the exempt first pull, at most half a
      // floor past it (RECEIVE_BUDGET_MS).
      summaries = await this.relay.listBlobs(
        mailboxId,
        mailbox.inboxPullToken,
        Math.max(1, remainingMs() - this.minPullDeadlineMs),
      );
    } catch (error) {
      report.failure = asRelayError(error);
      return report;
    }

    // The relay chooses this list, so it can repeat an id to make us pull twice and it can
    // make it arbitrarily long. Both are bounded here rather than trusted.
    const ids: string[] = [];
    const seen = new Set<string>();
    for (const summary of summaries) {
      if (seen.has(summary.blobId)) continue;
      seen.add(summary.blobId);
      ids.push(summary.blobId);
      if (ids.length >= MAX_PULLS_PER_RECEIVE) break;
    }
    report.listed = ids.length;

    let attempted = 0;
    for (const blobId of ids) {
      // THE VAULT CAN HAVE EMPTIED ITSELF SINCE THE LAST AWAIT, and a pull issued after that
      // is a message DESTROYED rather than a pass interrupted. The chain is short and every
      // link of it already exists: the relay deletes the blob inside its critical section
      // before the bytes reach the wire (MIN_PULL_DEADLINE_MS above), so by the time the
      // answer arrives the only copy is in this process; open() below is handed
      // host.keys(), which throws 'vault: locked' out of the vault's own assertUnlocked; the
      // catch around it counts the blob as `unopenable`, which this file documents as RELAY
      // NOISE and which no summary prints. So the message is gone, the count blames the one
      // component that did nothing wrong, and nothing anywhere tells the person.
      //
      // CHECKED BEFORE THE REQUEST, NEVER AFTER IT, and that ordering is the whole fix
      // (bulkhead): an id that was never asked for is still in the mailbox and arrives on
      // the next refresh, by the same delete-on-pull rule that makes an abandoned pull
      // unsafe. Asked WITHOUT touching the vault, because every other method here throws
      // once it is locked and because a read would rearm the very timer that fired.
      //
      // THE REMAINING WINDOW IS NAMED, not closed, and it is WIDER than the pull in flight.
      // Two messages are lost when a lock lands mid-pass, not one:
      //   1. the blob of a pull this check has already allowed. The bytes come back to a
      //      process with no keys and nowhere durable to put them.
      //   2. EVERY MESSAGE THIS PASS HAD ALREADY ACCEPTED. Inbound records are pushed into
      //      the live vault array above and become durable only at the single persist()
      //      below, which the throw at the end of this function pre-empts and which could
      //      not run anyway (persist -> snapshot -> assertUnlocked). MAX_PULLS_PER_RECEIVE
      //      is 32, so that is up to 31 messages, all deleted at the relay by delete-on-pull
      //      and present nowhere else.
      // Closing (2) needs a persist per accept, which re-seals the whole vault per message
      // and is therefore quadratic in history length: a design change, tracked as a residual
      // rather than smuggled into a bug fix. What this check removes is the case where the
      // vault was ALREADY locked, which is every pull after the first stall, and that is the
      // common case rather than the exotic one.
      if (this.host.isLocked()) break;
      const left = remainingMs();
      // A FLOOR, not a positive check. Starting a pull with a sliver of budget aborts it
      // mid-body, and delete-on-pull means the relay has already destroyed the blob by
      // then, so the message is gone for good. An id left unpulled is still in the mailbox.
      // Stop the pass rather than skip ahead: the ids are equally expensive, so a later one
      // would not fit either, and trying would just spend the floor on another hole.
      //
      // THE FIRST PULL MAY SPEND THE RESERVATION, and only the first: the floor was withheld
      // from the list's deadline for it, so a few milliseconds of accounting between the
      // list returning and this line must not be able to refuse a pull that was already paid
      // for. That is what stops a pass from being structurally unable to collect anything,
      // which is the failure with no self-repair (nothing is destroyed, but nothing is ever
      // collected either, and no later refresh helps).
      //
      // THE EXEMPTION IS BOUNDED BY WHAT IS LEFT OF THE RESERVATION, because "already paid
      // for" stops being true the moment the list overruns its own deadline: a frozen tab or
      // a suspended machine hands back control with the budget spent and the reservation
      // spent with it. Half of it has to survive. Below that the pull is refused like any
      // other, which costs one poll interval and destroys nothing, and the alternative is
      // starting a pull with the bare floor on a link that has just demonstrated it is
      // slower than that, which under delete-on-pull destroys the message permanently.
      const first = attempted === 0;
      const spendReservation = first && left * 2 >= this.minPullDeadlineMs;
      if (left < this.minPullDeadlineMs && !spendReservation) {
        report.failure ??= new RelayError(
          'timeout',
          'relay: the pass ran out of time before every waiting message was collected',
        );
        break;
      }
      // What this pull is allowed to take. Normally what is genuinely left, which the check
      // above has just proved is at least the floor. On the exempt first pull it is the
      // LARGER of what is left and the reservation, so a reserved floor cannot be shrunk
      // into a sliver by the clock. The overrun that buys is bounded by the exemption's own
      // condition: at least half the reservation was still there, so the pass can end at
      // most half a floor past the budget. The invariant every branch keeps is the one
      // MIN_PULL_DEADLINE_MS states, that no pull is started with less than the floor.
      const within = spendReservation ? Math.max(left, this.minPullDeadlineMs) : left;
      attempted++;
      let bytes: Uint8Array | null;
      try {
        bytes = await this.relay.pullBlob(mailboxId, blobId, mailbox.inboxPullToken, within);
      } catch (error) {
        const relayError = asRelayError(error);
        if (relayError.failure === 'oversize' || relayError.failure === 'malformed') {
          // A defect in ONE answer. The blob is gone either way (delete-on-pull), so there
          // is nothing to retry, but the next id is still worth asking for.
          report.defective++;
          continue;
        }
        // STARTED AND UNDECIDED, which is the one outcome where this device cannot say
        // whether the message survived: the request went out, the relay deletes before it
        // writes, and a failure here covers everything from "never arrived" to "deleted and
        // then the connection died". Counted rather than folded into the failure, because
        // the UI has to be able to tell this apart from a list that timed out, where nothing
        // was pulled and therefore nothing could have been destroyed.
        //
        // AN ANSWER IS NOT AN INTERRUPTION. The discriminator is the one the transport
        // actually establishes: RelayError carries a `status` only when the relay answered
        // (relay-client.ts failureFor), and no status at all when the deadline fired or the
        // connection died. The shipped relay decides a pull's 401 and 429 in `_authz`, which
        // runs BEFORE `store.pull_blob` deletes anything, so those answers leave the blob in
        // the mailbox for the next refresh and saying otherwise printed a false loss under a
        // true "wait a little and ask again". A 5xx is the exception and stays counted: the
        // relay's `_guarded` wrapper turns any unexpected exception into a 500 around the
        // WHOLE route, delete included, so that one is genuinely undecidable. See
        // ReceiveReport.interrupted for why a lying relay does not change this.
        if (relayError.status === undefined || relayError.status >= 500) report.interrupted++;
        report.failure = relayError;
        break;
      }
      if (bytes === null) {
        report.vanished++;
        continue;
      }
      let opened;
      try {
        opened = await open(this.host.keys(), card, bytes, { nowMs });
      } catch {
        // Silent to the user on purpose. The message did not come from a verified peer, so
        // there is no peer to attribute it to.
        report.unopenable++;
        continue;
      }
      const verdict = this.host.replay().admit(opened.senderId, opened.timestampMs, opened.msgId, nowMs);
      if (!verdict.accepted) {
        if (verdict.reason === 'duplicate') report.duplicate++;
        else report.stale++;
        continue;
      }
      this.host.messages().push({
        peerId: Uint8Array.from(peerId),
        direction: 'in',
        timestampMs: opened.timestampMs,
        body: opened.body,
        msgId: opened.msgId,
        // WHEN IT REACHED THIS DEVICE, which is the only part of an inbound message's
        // timing this device witnessed. `timestampMs` is the SENDER's authenticated clock,
        // and the gap between the two belongs to the relay: it may hold a blob for as long
        // as the acceptance window and release it whenever it likes. Recorded so a message
        // the relay sat on can be shown as having just turned up, rather than quietly
        // filed into the middle of a thread the reader has already read.
        receivedAtMs: nowMs,
      });
      report.accepted++;
    }
    // Ids the relay listed that were never asked for, because the loop stopped first. They
    // were not pulled, so they were not deleted, and the next refresh asks again.
    report.unread = ids.length - attempted;

    // A PASS THAT ENDED IN A LOCK IS NOT A PASS THAT COLLECTED NOTHING, and the difference
    // has to reach the caller as a THROW. ui/app.ts wraps every relay call in one function
    // that keeps a `locked` flag, and the flag is what stops it re-enabling the composer and
    // repainting a conversation out of a vault with no keys in it; that flag is set in a
    // catch, so a report that RESOLVES walks straight past it and the repaint throws where
    // nobody is holding it. Measured, not inferred: before this line, a lock landing while
    // the list was held produced `Unhandled Rejection: Error: vault: locked` out of paint().
    //
    // Before the persist rather than after it, because persist() cannot run on a locked
    // vault either (snapshot() goes through assertUnlocked), so the only thing checking last
    // would buy is a less specific error out of a different file.
    if (this.host.isLocked()) {
      throw new MessagingError(
        'locked',
        'messaging: the vault locked itself part way through this pass',
      );
    }

    // The obligation: an admit that never reaches a blob is lost at lock AND re-acceptable
    // after reopen. This runs before the caller is told anything, including on the path
    // where a transport failure broke the loop.
    if (report.accepted > 0) await this.host.persist();
    return report;
  }

  /**
   * One refresh: hand over anything queued, then collect anything waiting.
   *
   * TWO BUDGETS, NOT ONE, and the caller is the reason they are both needed: ui/app.ts
   * disables the composer for the whole of this call, so the ceiling a stalling relay can
   * reach is FLUSH_BUDGET_MS plus RECEIVE_BUDGET_MS plus the bounded overrun
   * MIN_PULL_DEADLINE_MS names. That sum is what docs/NAMED-RESIDUALS.md publishes; it is
   * longer than one poll interval, which costs a skipped refresh and nothing else, because
   * the poll and the buttons share one busy flag.
   */
  async sync(
    peerId: Uint8Array,
    nowMs: number = Date.now(),
  ): Promise<{ flush: FlushReport; receive: ReceiveReport }> {
    const flush = await this.flush(peerId);
    const receive = await this.receive(peerId, nowMs);
    return { flush, receive };
  }

  private require(peerId: Uint8Array): { card: ContactCard; mailbox: MailboxPairing } {
    const card = this.host.cardFor(peerId);
    if (!card) throw new MessagingError('not-pinned', 'messaging: that identity is not pinned');
    const mailbox = this.host.mailboxFor(peerId);
    if (!mailbox) {
      throw new MessagingError('no-mailbox', 'messaging: this pairing has no mailboxes');
    }
    return { card, mailbox };
  }
}

/**
 * The local key for an outbound record. Outbound bytes cannot be opened by their own sender
 * (open() requires recipient_id to be us), so there is no authenticated msg-id to use, and
 * this is a join key for the interface rather than a protocol value. Domain-separated so it
 * can never be mistaken for one.
 */
function outboxId(wire: Uint8Array): Uint8Array {
  return sha512(concatBytes(CTX_OUTBOX_ID, wire));
}

/**
 * One caller-supplied millisecond option, as a whole number of at least 1.
 *
 * The non-finite case is not defensive tidying. NaN loses every comparison, so it never
 * fails closed anywhere: it propagates. MEASURED with the guard removed, on three links.
 * Every deadline in the pass becomes NaN, which setTimeout reads as zero, and what that
 * costs depends on which phase is slower than nothing:
 *
 *   - a link where the LIST takes real time (100ms was enough): the pass aborts its own
 *     list, listed=0, and collects nothing at all for as long as the caller keeps passing
 *     NaN. This is the ordinary outcome;
 *   - a fast list with a body that takes real time: listed=3, accepted=0, interrupted=1, and
 *     one message unrecoverable afterwards. The first pull is started with a zero-length
 *     deadline and aborts mid-body, which under delete-on-pull destroys it, and since a
 *     failed pull stops the pass it is one message per refresh rather than the whole batch;
 *   - an everything-in-memory stub: nothing at all happens, because the response resolves
 *     before a zero-length timer can fire. Worth writing down, because it is the link every
 *     test runs on and it is the one that hides this.
 *
 * Nothing in the app passes one, and that is exactly the argument for making the shape
 * unrepresentable here rather than trusting every future caller to have read this file.
 */
function msOption(value: number | undefined, fallback: number): number {
  const chosen = value ?? fallback;
  return Number.isFinite(chosen) ? Math.max(1, Math.floor(chosen)) : fallback;
}

/**
 * The clock the BUDGET is measured with: monotonic where one exists, wall clock where it
 * does not. `performance.now()` is in every browser this targets and in Node, and it is the
 * only one of the two that a time sync cannot step (see RECEIVE_BUDGET_MS for what a step
 * does to a budget).
 *
 * Resolved rather than imported, and re-resolved per pass, because "there is no
 * `performance`" is a real environment (an old embedded runtime, a stripped test double) and
 * a messenger that throws on a missing timing API is worse than one that measures with a
 * clock that can move. The reading itself is checked, not just the shape of the object: a
 * `now` that answers something other than a finite number is a broken clock whatever its
 * type says.
 */
function monotonicClock(): () => number {
  const perf = (globalThis as { performance?: { now?: () => number } }).performance;
  if (perf && typeof perf.now === 'function' && Number.isFinite(perf.now())) {
    return () => perf.now!();
  }
  return () => Date.now();
}

function compareIds(a: MessageRecord, b: MessageRecord): number {
  if (!a.msgId || !b.msgId) return 0;
  return toHex(a.msgId) < toHex(b.msgId) ? -1 : 1;
}

/** Anything thrown out of the relay client, as a RelayError. Nothing else reaches here. */
function asRelayError(error: unknown): RelayError {
  if (error instanceof RelayError) return error;
  return new RelayError('network', `relay: ${error instanceof Error ? error.message : String(error)}`);
}
