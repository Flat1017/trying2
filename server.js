const crypto = require("crypto");
const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const envUserId = process.env.USE_ID;
const envUserPassword = process.env.USER_PASSWORD;

const usersPath = path.join(__dirname, "users.json");
const usersData = JSON.parse(fs.readFileSync(usersPath, "utf8"));

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const hashPassword = (password, salt, iterations, algorithm) =>
  crypto.pbkdf2Sync(password, salt, iterations, 32, algorithm).toString("hex");

const getUserById = (id) => usersData.users.find((user) => user.id === id);

const loginWithEnvCredentials = (id, password) => {
  if (!envUserId || !envUserPassword) {
    return null;
  }

  if (id !== envUserId || password !== envUserPassword) {
    return false;
  }

  return { id: envUserId };
};

app.post("/api/login", (req, res) => {
  const { id, password } = req.body;

  if (!id || !password) {
    return res.status(400).json({ message: "IDとパスワードを入力してください。" });
  }

  const envUser = loginWithEnvCredentials(id, password);
  if (envUser === false) {
    return res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
  }

  if (envUser) {
    const token = jwt.sign({ sub: envUser.id }, jwtSecret, { expiresIn: "2h" });
    return res.json({ token, user: { id: envUser.id } });
  }

  const user = getUserById(id);
  if (!user) {
    return res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
  }

  const { salt, hash, iterations, algorithm } = user.password;
  const computedHash = hashPassword(password, salt, iterations, algorithm);

  if (
    !crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(computedHash, "hex")
    )
  ) {
    return res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
  }

  const token = jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: "2h" });
  return res.json({ token, user: { id: user.id } });
});

app.get("/api/me", (req, res) => {
  const authHeader = req.headers.authorization || "";
  const [type, token] = authHeader.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "認証情報が必要です。" });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    return res.json({ id: payload.sub });
  } catch (error) {
    return res.status(401).json({ message: "トークンが無効です。" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
