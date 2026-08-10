// The pairing ceremony as a state machine, with no DOM in it.
//
// Two reasons it is separated from the screens. It is the part with security-relevant
// transitions (a refusal must be terminal, the words must be unreachable without a
// verified peer proof), so the suite drives THIS, not a rendered page. And progdisc: the
// machine emits exactly one decision per view, which is what the screens render.
//
// Three turns, alternating, six optical payloads in total. See src/pairing-session.ts for
// why three and not two.
//
//   show-first (A)              scan-first (B)
//   1 show  card + info         1 scan  card + info
//   2 scan  card+info+proof     2 show  card + info + proof
//     finalize -> words           prove
//   3 show  proof               3 scan  proof
//     compare                     finalize -> words, compare
//
// `info` is the nonce plus, when this device reserved one, the mailbox coordinate its peer
// will write to (src/mailbox.ts). One payload rather than two because an optional second
// stream races the required ones and is silently dropped.
//
// EVERY refusal is terminal. There is no path from `refused` back into the ceremony, and
// no refusal offers "try again" as its advice, because for all of them retrying is the
// wrong move (copy.ts).

import type { ContactCard } from '../card.js';
import type { AcceptResult, AcceptStatus } from '../contacts.js';
import type { CardFrameStream } from '../optical.js';
import type { MailboxPairing } from '../vault.js';
import {
  classifyPairingPayload,
  type PairingPayloadKind,
  type PairingSession,
} from '../pairing-session.js';
import { bytesEqual, toHex } from '../bytes.js';
import {
  REFUSAL_CANCELLED,
  REFUSAL_MISMATCH,
  REFUSAL_PROOF,
  REFUSAL_ROLLBACK,
  STEP_COPY,
  refusalForScanError,
  type Refusal,
} from './copy.js';

export type CeremonyRole = 'show-first' | 'scan-first';
export type CeremonyPhase = 'show' | 'scan' | 'compare' | 'paired' | 'refused';
export type OfferResult = 'accepted' | 'duplicate' | 'ignored' | 'refused';

export const CEREMONY_STEPS = 3;

/** Our half of this pairing's mailboxes: the box WE read, and the token that reads it. */
export interface OwnInbox {
  readonly id: Uint8Array; // 16
  readonly pullToken: string;
}

/** What the ceremony needs from the vault: classify a card, and make a pin DURABLE. */
export interface ContactPinner {
  classify(card: ContactCard): AcceptResult;
  /**
   * Pin (or supersede) and persist before resolving. `Vault.save()` is what makes vault
   * state durable, so a commit that resolves without one is a pin that disappears at lock.
   * The mailboxes ride the SAME write as the pin: a pinned contact with no coordinates and
   * coordinates with no pinned contact are both states the interface would have to explain.
   */
  commit(card: ContactCard, status: AcceptStatus, mailbox?: MailboxPairing): Promise<void>;
}

export interface PeerSummary {
  readonly identityHex: string;
  readonly serial: number;
}

export interface CeremonyView {
  readonly phase: CeremonyPhase;
  readonly step: number;
  readonly totalSteps: number;
  readonly heading: string;
  readonly lede: string;
  /** `show` only: streams are played in order and cycled, so the peer can catch all of them. */
  readonly playlist: readonly CardFrameStream[];
  /** `scan` only. */
  readonly expecting: readonly PairingPayloadKind[];
  readonly collected: readonly PairingPayloadKind[];
  /** `compare` and later. Six BIP-39 words, in order, or empty. */
  readonly words: readonly string[];
  /** True when this peer is already pinned with an OLDER card (contacts.ts `supersede`). */
  readonly supersede: boolean;
  readonly peer: PeerSummary | undefined;
  readonly refusal: Refusal | undefined;
  /** True when both halves of this pairing's mailboxes are in hand, so messaging will work. */
  readonly mailboxLinked: boolean;
}

export class PairingCeremony {
  private phase: CeremonyPhase;
  private step = 1;
  private heading: string;
  private lede: string;
  private playlist: CardFrameStream[] = [];
  private expecting: PairingPayloadKind[] = [];
  private readonly collected = new Set<PairingPayloadKind>();
  private words: string[] = [];
  private supersede = false;
  private peerStatus: AcceptStatus | undefined;
  private refusal: Refusal | undefined;

  private constructor(
    private readonly session: PairingSession,
    private readonly pinner: ContactPinner,
    readonly role: CeremonyRole,
    private readonly ownInbox: OwnInbox | undefined,
  ) {
    if (role === 'show-first') {
      this.phase = 'show';
      this.playlist = [session.cardFrames, session.infoFrames];
      this.heading = STEP_COPY.showCard.heading;
      this.lede = STEP_COPY.showCard.lede;
    } else {
      this.phase = 'scan';
      this.expecting = ['card', 'info'];
      this.heading = STEP_COPY.scanPeer.heading;
      this.lede = STEP_COPY.scanPeer.lede;
    }
  }

  static begin(
    session: PairingSession,
    pinner: ContactPinner,
    role: CeremonyRole,
    ownInbox?: OwnInbox,
  ): PairingCeremony {
    return new PairingCeremony(session, pinner, role, ownInbox);
  }

  /**
   * Both halves or nothing. Half a pairing is a conversation that can send and not receive,
   * or the reverse, and neither is a state worth two more screens (anchor `secondsys`); the
   * paired screen says messaging is not connected and the fix is another ceremony.
   */
  private mailboxPairing(card: ContactCard): MailboxPairing | undefined {
    const peer = this.session.peerParts().mailbox;
    if (!this.ownInbox || !peer) return undefined;
    // The peer's signature proves the coordinate came from the peer, but the peer got its
    // mailbox from the same relay we did, so a relay serving both devices can hand out one
    // box twice. Then this device's own poll pulls its own outbound blob and delete-on-pull
    // destroys it, and both sides sit at "Handed to the relay" plus "0 new messages"
    // forever. Refuse the pairing instead: both halves or nothing, same as a missing half.
    if (bytesEqual(this.ownInbox.id, peer.id)) return undefined;
    return {
      peerId: Uint8Array.from(card.identityPub),
      inboxId: Uint8Array.from(this.ownInbox.id),
      inboxPullToken: this.ownInbox.pullToken,
      outboxId: Uint8Array.from(peer.id),
      outboxWriteCap: peer.writeCap,
    };
  }

  view(): CeremonyView {
    const card = this.session.peerParts().card;
    return {
      phase: this.phase,
      step: this.step,
      totalSteps: CEREMONY_STEPS,
      heading: this.heading,
      lede: this.lede,
      playlist: this.playlist,
      expecting: this.expecting,
      collected: [...this.collected],
      words: this.words,
      supersede: this.supersede,
      peer: card ? { identityHex: toHex(card.identityPub), serial: card.serial } : undefined,
      refusal: this.refusal,
      // Asks the same function that actually builds the pairing, rather than re-deriving
      // the condition. The two had already drifted once: this said "linked" for a
      // coordinate mailboxPairing() refuses, so the screen promised messaging the commit
      // would not create.
      mailboxLinked: card !== undefined && this.mailboxPairing(card) !== undefined,
    };
  }

  /** The human confirmed the peer captured what is on screen. Only meaningful while showing. */
  handOff(): void {
    if (this.phase !== 'show') return;
    if (this.role === 'show-first') {
      if (this.step === 1) {
        this.toScan(2, ['card', 'info', 'proof'], STEP_COPY.scanPeer);
      } else {
        this.phase = 'compare';
      }
      return;
    }
    this.toScan(3, ['proof'], STEP_COPY.scanProof);
  }

  /**
   * A completed optical payload arrived. Unexpected and duplicate payloads are ignored
   * rather than refused: the peer screen is cycling several streams and the camera is
   * pointed at a room, so both are ordinary.
   */
  async offer(payload: Uint8Array): Promise<OfferResult> {
    if (this.phase !== 'scan') return 'ignored';
    const kind = classifyPairingPayload(payload);
    if (!this.expecting.includes(kind)) return 'ignored';
    if (this.collected.has(kind)) return 'duplicate';

    if (kind === 'card') {
      let card: ContactCard;
      try {
        card = this.session.acceptPeerCard(payload);
      } catch (error) {
        this.refuse(refusalForScanError(error));
        return 'refused';
      }
      const result = this.pinner.classify(card);
      // Refused here rather than after the words: making two people read six words aloud
      // and then telling them it could never have been saved is the wrong order.
      if (result.status === 'rejected') {
        this.refuse(REFUSAL_ROLLBACK);
        return 'refused';
      }
      this.peerStatus = result.status;
      this.supersede = result.status === 'supersede';
    } else if (kind === 'info') {
      try {
        this.session.acceptPeerInfo(payload);
      } catch (error) {
        // A malformed info payload or a coordinate signed by somebody else. Both are
        // refusals rather than noise: this payload carries the nonce the whole ceremony
        // rests on, so accepting a broken one and carrying on is not an option.
        this.refuse(refusalForScanError(error));
        return 'refused';
      }
    } else {
      this.session.acceptPeerProof(payload);
    }

    this.collected.add(kind);
    if (this.expecting.every((k) => this.collected.has(k))) await this.completeScan();
    return 'accepted';
  }

  /** The trust decision, taken by a human who just read six words out loud. */
  async confirmMatch(): Promise<void> {
    if (this.phase !== 'compare') return;
    const card = this.session.peerParts().card;
    if (!card) throw new Error('ceremony: no peer card at confirmation');
    // Re-classified rather than trusting the value stashed at scan time: the store is the
    // authority, and commit() has to be handed a status that matches it right now.
    const status = this.pinner.classify(card).status;
    if (status === 'rejected') {
      this.refuse(REFUSAL_ROLLBACK);
      return;
    }
    await this.pinner.commit(card, status, this.mailboxPairing(card));
    this.phase = 'paired';
  }

  confirmMismatch(): void {
    if (this.phase !== 'compare') return;
    this.refuse(REFUSAL_MISMATCH);
  }

  cancel(): void {
    if (this.phase === 'paired' || this.phase === 'refused') return;
    this.refuse(REFUSAL_CANCELLED);
  }

  private toScan(
    step: number,
    expecting: PairingPayloadKind[],
    copy: { heading: string; lede: string },
  ): void {
    this.phase = 'scan';
    this.step = step;
    this.expecting = expecting;
    this.collected.clear();
    this.playlist = [];
    this.heading = copy.heading;
    this.lede = copy.lede;
  }

  private toShow(
    step: number,
    playlist: CardFrameStream[],
    copy: { heading: string; lede: string },
  ): void {
    this.phase = 'show';
    this.step = step;
    this.playlist = playlist;
    this.expecting = [];
    this.collected.clear();
    this.heading = copy.heading;
    this.lede = copy.lede;
  }

  private async completeScan(): Promise<void> {
    if (this.role === 'scan-first' && this.step === 1) {
      const proofFrames = await this.session.prove();
      this.toShow(
        2,
        [this.session.cardFrames, this.session.infoFrames, proofFrames],
        STEP_COPY.showCardAndProof,
      );
      return;
    }

    const outcome = await this.session.finalize();
    if (!outcome.ok) {
      this.refuse(REFUSAL_PROOF);
      return;
    }
    this.words = [...outcome.safetyNumber.words];

    if (this.role === 'show-first') {
      // A verifies BEFORE it emits its own proof, so a peer that failed PoP never receives
      // a signature from us. B cannot do this; see src/pairing-session.ts.
      this.toShow(3, [this.session.proofFrames()], STEP_COPY.showProof);
      return;
    }
    this.phase = 'compare';
  }

  private refuse(refusal: Refusal): void {
    this.phase = 'refused';
    this.refusal = refusal;
    this.playlist = [];
    this.expecting = [];
    this.words = [];
  }
}
