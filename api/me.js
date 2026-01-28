const jwt = require("jsonwebtoken");

const { getJwtSecret } = require("./_auth");

module.exports = (req, res) => {
  if (req.method !== "GET") {
    res.status(405).json({ message: "Method Not Allowed" });
    return;
  }

  const authHeader = req.headers.authorization || "";
  const [type, token] = authHeader.split(" ");

  if (type !== "Bearer" || !token) {
    res.status(401).json({ message: "認証情報が必要です。" });
    return;
  }

  try {
    const payload = jwt.verify(token, getJwtSecret());
    res.json({ id: payload.sub });
  } catch (error) {
    res.status(401).json({ message: "トークンが無効です。" });
  }
};
