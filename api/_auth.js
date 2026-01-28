const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const usersPath = path.join(process.cwd(), "users.json");

const readUsers = () => {
  const raw = fs.readFileSync(usersPath, "utf8");
  return JSON.parse(raw);
};

const hashPassword = (password, salt, iterations, algorithm) =>
  crypto.pbkdf2Sync(password, salt, iterations, 32, algorithm).toString("hex");

const getUserById = (id) => {
  const usersData = readUsers();
  return usersData.users.find((user) => user.id === id);
};

const getEnvUser = (id, password) => {
  const envUserId = process.env.USER_ID;
  const envUserPassword = process.env.USER_PASSWORD;

  if (!envUserId || !envUserPassword) {
    return null;
  }

  if (id !== envUserId || password !== envUserPassword) {
    return false;
  }

  return { id: envUserId };
};

const getJwtSecret = () =>
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

module.exports = {
  getEnvUser,
  getJwtSecret,
  getUserById,
  hashPassword,
};
