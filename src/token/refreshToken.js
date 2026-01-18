const crypto = require("crypto");

// ランダムなリフレッシュトークン文字列を生成。
function createRefreshTokenString() {
  return crypto.randomBytes(64).toString("hex");
}

// リフレッシュトークンをハッシュ化。
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

module.exports = {
  createRefreshTokenString,
  hashToken,
};
