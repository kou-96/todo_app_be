const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

// すべてのユーザーを取得。
router.get("/", auth, async (req, res) => {
  try {
    const users = await pool.query(
      "SELECT id, email, created_at FROM users"
    );
    res.json(users.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("ユーザー取得エラー");
  }
});

// 認証済みユーザーを削除。
router.delete("/", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      "DELETE FROM users WHERE id = $1 RETURNING *",
      [userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "ユーザーが存在しません" });
    }

    res.json({ message: "ユーザーとTodoを削除しました" });
  } catch (err) {
    console.error(err);
    res.status(500).send("削除エラー");
  }
});

module.exports = router;
