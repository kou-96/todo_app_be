const app = require("./app");

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`サーバーがポート${PORT}で起動しました。`);
  console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
});
