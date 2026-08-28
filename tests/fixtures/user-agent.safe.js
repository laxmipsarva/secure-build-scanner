app.post("/api/admin/action", (req, res, next) => {
  requireApiKey(req, res, next);
});

app.post("/auth/login", (req, res) => {
  const userAgent = req.headers['user-agent'] || "";
  if (/sqlmap|nikto|nmap|masscan/i.test(userAgent)) {
    return res.sendStatus(403);
  }
  authenticate(req.body.username, req.body.password);
  res.sendStatus(200);
});
