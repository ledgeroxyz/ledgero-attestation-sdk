import type { Address, Hex } from "viem";

/** 32 zero bytes, used as the "empty" supportingDataHash for attestations with no supporting docs. */
export const ZERO_BYTES32: Hex = `0x${"0".repeat(64)}` as Hex;

/** The canonical zero address, used where a `subject` is not applicable. */
export const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";
