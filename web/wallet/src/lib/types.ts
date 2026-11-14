// Shared domain types mirroring the backend contract.

export type VaultSummary = {
  vault: string;
  name: string;
  policy?: string;
  members: number;
  threshold: number;
  // False while the vault is still in setup (no DKG key yet, so no address).
  active?: boolean;
};

export type StatusResponse = {
  phase: "new_profile" | "locked" | "home";
  network?: string;
  // Share encryption on the signer host: Enclave wrapping key or software sealing.
  secure_element?: "apple" | "software" | string;
  profile?: { name: string; id: string };
  vaults?: VaultSummary[];
};

export type InviteSlot = { slot: number; code: string; joined: boolean };

export type CeremonyStatus = {
  phase:
    | "waiting_for_members"
    | "compare_roster"
    | "creating_keys"
    | "back_up"
    | "waiting_for_backups"
    | "final_backup"
    | "connecting_relays"
    | "setup_interrupted"
    | "active";
  fingerprint?: string;
  invites?: InviteSlot[];
  // Count of members who have confirmed (the host sends a number, not a per-slot list).
  confirmations?: number;
  members: number;
  threshold: number;
};

export type Payment = {
  attempt: string;
  phase: string;
  recipient: string;
  amount_zat: string;
  ready_to_send: boolean;
  finish_requested?: boolean;
  error?: string | null;
  txid?: string | null;
  direction?: "sent" | "received";
  amount_is_net?: boolean;
  mined_height?: number | null;
  fee_zat?: string | null;
  signers?: number[];
};

export type PaymentSession = {
  phase: string;
  finish_requested: boolean;
  signatures_received: boolean;
  intent: {
    proposer: number;
    signers: number[];
    recipient: string;
    amount_zat: number;
    fee_zat: number;
    open_approval: boolean;
  };
};

export type PaymentReview = {
  review_token: string;
  recipient: string;
  amount_zat: string;
  fee_zat: string;
  memo: string;
};
