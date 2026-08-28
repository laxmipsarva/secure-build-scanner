import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.post("/auth/login", loginLimiter, (req, res) => {
  authenticate(req.body.username, req.body.password);
  res.sendStatus(200);
});

app.post("/account/data", (req, res, next) => {
  fetchData().catch((err) => {
    console.error(err);
    res.status(500).json({ error: "internal server error" });
  });
});
