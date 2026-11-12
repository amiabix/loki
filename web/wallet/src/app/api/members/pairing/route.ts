import { readRegistrationBody, issuePairingChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    const origin = new URL(req.url).origin;
    if (req.headers.has("origin") && req.headers.get("origin") !== origin) throw new Error("wrong pairing origin");
    const body = await readRegistrationBody(req);
    return Response.json(await issuePairingChallenge(body, origin), { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 400 });
  }
}
