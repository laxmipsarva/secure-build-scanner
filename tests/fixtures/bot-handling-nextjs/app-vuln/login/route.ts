export async function POST(request: Request) {
  const { username, password } = await request.json();
  const ok = await authenticate(username, password);
  return Response.json({ ok });
}
