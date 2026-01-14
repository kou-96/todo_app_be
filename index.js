const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRES = "1m";
const REFRESH_TOKEN_EXPIRES_MIN = 1;

function createRefreshTokenString() {
  return crypto.randomBytes(64).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });
};

const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer "))
    return res.status(401).send("認証トークンなし");
  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).send("期限切れ");
  }
};

app.get("/users", auth, async (req, res) => {
  try {
    const users = await pool.query("SELECT id, email, created_at FROM users");
    res.json(users.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("ユーザー取得エラー");
  }
});

app.get("/todos", auth, async (req, res) => {
  try {
    const todos = await pool.query(
      "SELECT * FROM todos WHERE user_id = $1 ORDER BY id ASC",
      [req.user.id]
    );
    res.json(todos.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("取得エラー");
  }
});

app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !email.trim() || !password || !password.trim()) {
      return res.status(400).json({ message: "Email とパスワードを入力してください" });
    }

    const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "このメールアドレスは既に登録されています" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id",
      [email, hashed]
    );
    const user = newUser.rows[0];

    const accessToken = generateAccessToken(user);
    const refreshToken = createRefreshTokenString();
    const hashedToken = hashToken(refreshToken);

    await pool.query(
      "INSERT INTO refresh_tokens (token_hash, user_id, expiry, revoked, created_at) VALUES ($1, $2, now() + make_interval(mins => $3), false, now())",
      [hashedToken, user.id, REFRESH_TOKEN_EXPIRES_MIN]
    );

    res.status(201).json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).send("ユーザー作成エラー");
  }
});

app.post("/login", async (req, res) => {
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

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).send("ログインエラー");
  }
});

app.put("/logout", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    await pool.query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1", [userId]);
    res.json({ message: "ログアウトしました" });
  } catch (err) {
    res.status(500).json({ message: "ログアウトエラー" });
  }
});

app.post("/token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ message: "リフレッシュトークンなし" });

    const hashedToken = hashToken(refreshToken);
    const result = await pool.query(
      "SELECT id, user_id, expiry, revoked FROM refresh_tokens WHERE token_hash = $1",
      [hashedToken]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: "リフレッシュトークン無効" });
    }

    const row = result.rows[0];
    if (row.revoked) return res.status(403).json({ message: "リフレッシュトークンは取り消されています" });

    const now = new Date();
    if (row.expiry < now) {
      await pool.query("UPDATE refresh_tokens SET revoked = true WHERE id = $1", [row.id]);
      return res.status(403).json({ message: "リフレッシュトークン期限切れ" });
    }

    await pool.query("BEGIN");
    try {
      await pool.query("UPDATE refresh_tokens SET revoked = true WHERE id = $1", [row.id]);

      const newRefreshToken = createRefreshTokenString();
      const newHash = hashToken(newRefreshToken);
      const newExpiry = new Date();
      newExpiry.setMinutes(newExpiry.getMinutes() + REFRESH_TOKEN_EXPIRES_MIN);

      await pool.query(
        "INSERT INTO refresh_tokens (token_hash, user_id, expiry, revoked, created_at) VALUES ($1, $2, $3, false, now())",
        [newHash, row.user_id, newExpiry]
      );

      const newAccessToken = generateAccessToken({ id: row.user_id });
      await pool.query("COMMIT");
      res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    } catch (innerErr) {
      await pool.query("ROLLBACK");
      console.error("token rotation error:", innerErr);
      return res.status(500).json({ message: "トークン更新エラー" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "トークン処理エラー" });
  }
});

app.post("/todos", auth, async (req, res) => {
  try {
    const { title } = req.body;
    if (!title || !title.trim()) {
      return res.status(400).json({ message: "タイトルを入力してください" });
    }
    const newTodo = await pool.query(
      "INSERT INTO todos (title, user_id) VALUES ($1, $2) RETURNING *",
      [title, req.user.id]
    );
    res.status(201).json(newTodo.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Todo作成エラー");
  }
});

app.put("/todos/:id", auth, async (req, res) => {
  try {
    const todoId = req.params.id;
    const userId = req.user.id;
    const { title, is_complete } = req.body;

    const result = await pool.query(
      "UPDATE todos SET title = $1, is_complete = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
      [title, is_complete, todoId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(403).json({ message: "他のユーザーのTodoは変更できません" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Todo更新エラー");
  }
});

app.delete("/users", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING *", [userId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: "ユーザーが存在しません" });
    }
    res.json({ message: "ユーザーとTodoを削除しました" });
  } catch (err) {
    console.error(err);
    res.status(500).send("削除エラー");
  }
});

app.delete("/todos/:id", auth, async (req, res) => {
  try {
    const todoId = req.params.id;
    const userId = req.user.id;

    const result = await pool.query(
      "DELETE FROM todos WHERE id = $1 AND user_id = $2 RETURNING *",
      [todoId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(403).json({ message: "他のユーザーのTodoは削除できません" });
    }

    res.json({ message: "Todoを削除しました", todo: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send("Todo削除エラー");
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`サーバーがポート${PORT}で起動しました。`);
});
