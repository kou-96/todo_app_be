const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db");

// アクセストークンを生成する関数。
const { generateAccessToken } = require("../token/accessToken");
// リフレッシュトークン関連の関数。
const { createRefreshTokenString, hashToken } = require("../token/refreshToken");
// 認証済みユーザーのみ通すミドルウェア。
const auth = require("../middleware/auth");

const { cookieOptions } = require("../config/cookie");

const router = express.Router();

// リフレッシュトークンの有効期限。
// 本当は長く設定すべきだが、動作確認のために短くしている。
const REFRESH_TOKEN_EXPIRES_MIN = 1;

router.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !email.trim() || !password || !password.trim()) {
      return res.status(400).json({ message: "Email とパスワードを入力してください" });
    }

    // 既に登録されているメールアドレスか確認。
    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "このメールアドレスは既に登録されています" });
    }
    // パスワードをbcryptでハッシュ化して保存。
    const hashed = await bcrypt.hash(password, 10);
    // ユーザーを作成。
    const newUser = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id",
      [email, hashed]
    );
    const user = newUser.rows[0];
    // トークンを生成してCookieに保存。
    const accessToken = generateAccessToken(user);
    // リフレッシュトークンを作成してDBに保存。
    const refreshToken = createRefreshTokenString();
    // リフレッシュトークンをハッシュ化させてDBに保存。
    const hashedToken = hashToken(refreshToken);
    
    // ハッシュ化したリフレッシュトークンをDBに保存。
    await pool.query(
      "INSERT INTO refresh_tokens (token_hash, user_id, expiry, revoked, created_at) VALUES ($1, $2, now() + make_interval(mins => $3), false, now())",
      [hashedToken, user.id, REFRESH_TOKEN_EXPIRES_MIN]
    );

    // Cookieにアクセストークンを保存。
    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 60 * 1000
    });
    // Cookieにリフレッシュトークンを保存。
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TOKEN_EXPIRES_MIN * 60 * 1000
    });

    res.status(201).json({ message: "ユーザーを作成しました" });
  } catch (err) {
    console.error(err);
    res.status(500).send("ユーザー作成エラー");
  }
});

router.post("/login", async (req, res) => {
   try {
    const { email, password } = req.body;
    if (!email || !email.trim() || !password || !password.trim()) {
      return res.status(400).json({ message: "Emailとpasswordを入力してください" });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: "Emailまたはpasswordが間違っています。" });
    }

    const user = userResult.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(400).json({ message: "Emailまたはpasswordが間違っています。" });
    }

    await pool.query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1", [user.id]);

    const accessToken = generateAccessToken(user);
    const refreshToken = createRefreshTokenString();
    const hashedToken = hashToken(refreshToken);

    await pool.query(
      "INSERT INTO refresh_tokens (token_hash, user_id, expiry, revoked, created_at) VALUES ($1, $2, now() + make_interval(mins => $3), false, now())",
      [hashedToken, user.id, REFRESH_TOKEN_EXPIRES_MIN]
    );

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 60 * 1000
    });
    
    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TOKEN_EXPIRES_MIN * 60 * 1000
    });

    res.json({ message: "ログインしました"});
  } catch (err) {
    console.error(err);
    res.status(500).send("ログインエラー");
  }
});

router.post("/token", async (req, res) => {
  const client = await pool.connect();

  try {
    // リフレッシュトークンを取得。
    const refreshToken = req.body.refreshToken || req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "認証に失敗しました" });
    }

    const hashedToken = hashToken(refreshToken);

    await client.query("BEGIN");

    // トークンが存在するかを確認。
    const result = await client.query(
      `
      SELECT id, user_id, expiry, revoked
      FROM refresh_tokens
      WHERE token_hash = $1
      FOR UPDATE
      `,
      [hashedToken]
    );

    if (result.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(401).json({ message: "認証に失敗しました" });
    }

    const tokenRow = result.rows[0];

    // 失効済みトークンの再利用を防ぐため、認証を拒否する。
    if (tokenRow.revoked) {
      await client.query("ROLLBACK");
      return res.status(401).json({ message: "認証に失敗しました" });
    }

    // 有効期限をチェック。
    const now = new Date();
    if (new Date(tokenRow.expiry) < now) {
      await client.query(
        "UPDATE refresh_tokens SET revoked = true WHERE id = $1",
        [tokenRow.id]
      );
      await client.query("COMMIT");
      return res.status(401).json({ message: "認証に失敗しました" });
    }

    // 未使用のリフレッシュトークンを失効させ、
    // すでに使用されたリフレッシュトークンを認証エラーにする事で、
    // 再利用を防止する。
    const revokeResult = await client.query(
      `
      UPDATE refresh_tokens
      SET revoked = true
      WHERE id = $1 AND revoked = false
      `,
      [tokenRow.id]
    );

    if (revokeResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(401).json({ message: "認証に失敗しました" });
    }

    // 新しいリフレッシュトークンを発行。
    const newRefreshToken = createRefreshTokenString();
    // ハッシュ化して保存。
    const newHashedToken = hashToken(newRefreshToken);
    // 新しい有効期限を設定。
    const newExpiry = new Date();
    newExpiry.setMinutes(
      newExpiry.getMinutes() + REFRESH_TOKEN_EXPIRES_MIN
    );

    await client.query(
      `
      INSERT INTO refresh_tokens
        (token_hash, user_id, expiry, revoked, created_at)
      VALUES
        ($1, $2, $3, false, now())
      `,
      [newHashedToken, tokenRow.user_id, newExpiry]
    );

    // 新しいアクセストークンを発行。
    const newAccessToken = generateAccessToken({
      id: tokenRow.user_id
    });

    await client.query("COMMIT");

    // Cookieを再設定。
    res.cookie("accessToken", newAccessToken, {
  ...cookieOptions,
  maxAge: 60 * 1000
});

    res.cookie("refreshToken", newRefreshToken, {
  ...cookieOptions,
  maxAge: REFRESH_TOKEN_EXPIRES_MIN * 60 * 1000
});


    return res.json({ message: "トークンを更新しました" });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("refresh token error:", err);
    return res.status(500).json({ message: "サーバーエラー" });
  } finally {
    client.release();
  }
});

router.put("/logout", auth, async (req, res) => {
 try {
    const userId = req.user.id;
    await pool.query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1", [userId]);
    
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    
    res.json({ message: "ログアウトしました" });
  } catch (err) {
    res.status(500).json({ message: "ログアウトエラー" });
  }
});

module.exports = router;
