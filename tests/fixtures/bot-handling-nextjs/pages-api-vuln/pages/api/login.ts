export default function handler(req, res) {
  if (req.method === "POST") {
    authenticate(req.body.username, req.body.password);
    res.status(200).json({ ok: true });
  }
}
