const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

module.exports = (req, res, next) => {
  // Authorization ヘッダーを取得。
  const authHeader = req.headers.authorization;
  // Cookieに保存されているアクセストークンを取得。
  const cookieToken = req.cookies.accessToken;

  // BearerまたはCookieからトークンを取得。
  // なければnullになる。
  const token =
    (authHeader && authHeader.startsWith("Bearer ") && authHeader.split(" ")[1]) ||
    cookieToken ||
    null;

  // トークンが存在しない場合は未認証になる。
  if (!token) return res.status(401).send("認証トークンなし");

  try {
    // トークンを検証。
    const payload = jwt.verify(token, JWT_SECRET);
    // 検証済みユーザー情報を req.user に保存。
    req.user = payload;
    next();
  } catch {
    res.status(401).send("期限切れ");
  }
};
