const NODE_ENV = process.env.NODE_ENV || 'development';

module.exports = {
  // 本番環境かどうかを判定する為に必要。
  isProd: NODE_ENV === 'production',
};
