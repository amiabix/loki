import { admitAttempt, clientAddress, refusal } from "@/lib/admission-limits";
import { readRegistrationBody, issueRegistrationChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    const client = clientAddress(req);
    admitAttempt(client);
    const body = await readRegistrationBody(req);
    return Response.json(await issueRegistrationChallenge(body, new URL(req.url).origin, client));
  } catch (error) {
    return refusal(error);
  }
}
