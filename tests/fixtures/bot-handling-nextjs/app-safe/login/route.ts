import { rateLimit } from "@/lib/rate-limit";

export async function POST(request: Request) {
  await rateLimit(request);
  const { username, password } = await request.json();
  const ok = await authenticate(username, password);
  return Response.json({ ok });
}
