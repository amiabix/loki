import { readRegistrationBody, issueRegistrationChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    const body = await readRegistrationBody(req);
    return Response.json(await issueRegistrationChallenge(body, new URL(req.url).origin));
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 400 });
  }
}
