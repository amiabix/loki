// Shared domain types mirroring the backend contract.

export type VaultSummary = {
  vault: string;
  name: string;
  policy?: string;
  members: number;
  threshold: number;
};

export type StatusResponse = {
  phase: "new_profile" | "locked" | "home";
  network?: string;
  profile?: { name: string; id: string };
  vaults?: VaultSummary[];
};

export type InviteSlot = { slot: number; code: string; joined: boolean };
export type ConfirmationSlot = { slot: number; confirmed: boolean; matches: boolean };

export type CeremonyStatus = {
  phase:
    | "waiting_for_members"
    | "compare_roster"
    | "creating_keys"
    | "back_up"
    | "waiting_for_backups"
    | "final_backup"
    | "connecting_relays"
    | "active";
  fingerprint?: string;
  invites?: InviteSlot[];
  confirmations?: ConfirmationSlot[];
  members: number;
  threshold: number;
};

export type Payment = {
  attempt: string;
  phase: string;
  recipient: string;
  amount_zat: string;
  ready_to_send: boolean;
};

export type PaymentReview = {
  review_token: string;
  recipient: string;
  amount_zat: string;
  fee_zat: string;
  memo: string;
};
