import { connection } from "next/server";
import { signerConfigResponse } from "@/lib/signer-config";

/** The signer configuration LokiSigner shows and saves when it pairs with this coordinator. */
export async function GET() {
  await connection();
  return signerConfigResponse();
}
