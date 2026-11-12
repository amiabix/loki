import { connection } from "next/server";
import { readRegistrationBody, registerMember, slots } from "@/lib/members";

export async function GET() {
  await connection();
  return Response.json({ slots: slots() }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(req: Request) {
  try {
    const body = await readRegistrationBody(req);
    return Response.json({ member: await registerMember(body, new URL(req.url).origin) });
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 400 });
  }
}
