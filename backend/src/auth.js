import jwt from 'jsonwebtoken';

export function auth(requiredRole) {
  return (req, res, next) => {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Please log in.' });
    try {
      req.user = jwt.verify(token, process.env.JWT_SECRET);
      if (requiredRole && req.user.role !== requiredRole) return res.status(403).json({ error: 'Access denied.' });
      next();
    } catch {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
  };
}
