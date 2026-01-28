const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const { getEnvUser, getJwtSecret, getUserById, hashPassword } = require("./_auth");
const { getJsonBody } = require("./_body");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ message: "Method Not Allowed" });
    return;
  }

  let body;
  try {
    body = await getJsonBody(req);
  } catch (error) {
    res.status(400).json({ message: "不正なリクエストです。" });
    return;
  }

  const { id, password } = body || {};

  if (!id || !password) {
    res.status(400).json({ message: "IDとパスワードを入力してください。" });
    return;
  }

  const envUser = getEnvUser(id, password);
  if (envUser === false) {
    res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
    return;
  }

  if (envUser) {
    const token = jwt.sign({ sub: envUser.id }, getJwtSecret(), { expiresIn: "2h" });
    res.json({ token, user: { id: envUser.id } });
    return;
  }

  const user = getUserById(id);
  if (!user) {
    res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
    return;
  }

  const { salt, hash, iterations, algorithm } = user.password;
  const computedHash = hashPassword(password, salt, iterations, algorithm);

  if (
    !crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(computedHash, "hex")
    )
  ) {
    res.status(401).json({ message: "IDまたはパスワードが正しくありません。" });
    return;
  }

  const token = jwt.sign({ sub: user.id }, getJwtSecret(), { expiresIn: "2h" });
  res.json({ token, user: { id: user.id } });
};
