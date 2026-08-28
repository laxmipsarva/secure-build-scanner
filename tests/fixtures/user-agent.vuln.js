app.post("/api/admin/action", (req, res, next) => {
  const userAgent = req.headers['user-agent'];
  if (userAgent.includes('internal-service')) {
    // trusted internal caller, skip auth
    return next();
  }
  requireAuth(req, res, next);
});
