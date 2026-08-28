import rateLimit from "express-rate-limit";

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

export default function handler(req, res) {
  limiter(req, res, () => {
    if (req.method === "POST") {
      authenticate(req.body.username, req.body.password);
      res.status(200).json({ ok: true });
    }
  });
}
