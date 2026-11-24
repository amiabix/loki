export type VaultSummary = {
  vault: string;
  name: string;
  policy?: string;
  members: number;
  threshold: number;
  active?: boolean;
};

export type StatusResponse = {
  phase: "new_profile" | "locked" | "home";
  network?: string;
  secure_element?: "apple" | "software" | string;
  profile?: { name: string; id: string };
  vaults?: VaultSummary[];
  persisted?: boolean | null;
  relay?: string;
};

export type InviteSlot = { slot: number; code: string; joined: boolean };

export type CeremonyStatus = {
  phase:
    | "waiting_for_members"
    | "compare_roster"
    | "creating_keys"
    | "setup_interrupted"
    | "active";
  fingerprint?: string;
  roster_code?: string | null;
  roster_dialog?: "open" | "codes_differ" | null;
  invites?: InviteSlot[];
  confirmations?: number;
  confirmed?: boolean;
  error?: string;
  members: number;
  threshold: number;
};

export type Replaces = { attempt: string; cancel: boolean };

export type ChainProvenance = { chain_trust?: "provider_reported" };

export type Payment = {
  attempt: string;
  phase: string;
  proposer?: number;
  recipient: string;
  amount_zat: string;
  approvals?: number[];
  approval_requested?: boolean;
  can_discard?: boolean;
  can_dismiss?: boolean;
  can_send?: boolean;
  sending?: boolean;
  can_replace?: boolean;
  replaces?: Replaces | null;
  spent_by?: string | null;
  error?: string | null;
  txid?: string | null;
  direction?: "sent" | "received";
  amount_is_net?: boolean;
  mined_height?: number | null;
  fee_zat?: string | null;
  signers?: number[];
};

export type PaymentSession = ChainProvenance & {
  phase: string;
  signatures_received: boolean;
  txid?: string | null;
  spent_by?: string | null;
  replaces?: Replaces | null;
  approvals: number[];
  approval_requested: boolean;
  error?: string | null;
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
  intent_hash?: string;
  recipient: string;
  amount_zat: string;
  fee_zat: string;
  memo: string;
  replaces?: (Replaces & { phase?: string | null; recipient?: string | null; amount_zat?: string | null }) | null;
};
