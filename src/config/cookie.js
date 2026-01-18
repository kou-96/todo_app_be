const { isProd } = require("./env");

//Cookieを設定したときに使いまわせる共通オプション。
const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? "none" : "lax",
};

module.exports = { cookieOptions };
