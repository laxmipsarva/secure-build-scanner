app.post("/auth/login", (req, res) => {
  authenticate(req.body.username, req.body.password);
  res.sendStatus(200);
});

app.post("/account/data", (req, res, next) => {
  fetchData().catch((err) => {
    res.status(500).json({ error: err.stack });
  });
});
