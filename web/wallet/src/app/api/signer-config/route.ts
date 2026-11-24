import { connection } from "next/server";
import { signerConfigResponse } from "@/lib/signer-config";

export async function GET() {
  await connection();
  return signerConfigResponse();
}
