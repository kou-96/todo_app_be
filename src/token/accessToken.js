const jwt = require("jsonwebtoken");

// アクセストークンの有効期限。
// 短めに設定する事で、漏洩した時の被害が最小限になる。
const ACCESS_TOKEN_EXPIRES = "1m";

// ユーザー情報をもとにアクセストークンを生成。
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES }
  );
}

module.exports = { generateAccessToken };
