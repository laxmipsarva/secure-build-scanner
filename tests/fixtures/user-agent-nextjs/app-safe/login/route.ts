const BAD_USER_AGENTS = /sqlmap|nikto|nmap|masscan/i;

export async function POST(request: Request) {
  const userAgent = request.headers.get("user-agent") ?? "";
  if (BAD_USER_AGENTS.test(userAgent)) {
    return new Response("Forbidden", { status: 403 });
  }
  const { username, password } = await request.json();
  const ok = await authenticate(username, password);
  return Response.json({ ok });
}
