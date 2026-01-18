const express = require("express");
const pool = require("../db");
const auth = require("../middleware/auth");

const router = express.Router();

// 認証済みユーザーのTodoをすべて取得。
router.get("/", auth, async (req, res) => {
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

// 新しいTodoを作成。
router.post("/", auth, async (req, res) => {
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

// 指定したIDのTodoを更新。
router.put("/:id", auth, async (req, res) => {
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

// 指定したIDのTodoを削除。
router.delete("/:id", auth, async (req, res) => {
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

module.exports = router;
