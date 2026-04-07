/**
 * Sample Express app with routes — for testing.
 */

const express = require('express');
const app = express();

const authMiddleware = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
};

// Public routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Protected routes
app.get('/api/users', authMiddleware, (req, res) => {
  res.json({ users: [] });
});

app.post('/api/users', authMiddleware, (req, res) => {
  res.status(201).json({ created: true });
});

app.get('/api/users/:id', authMiddleware, (req, res) => {
  res.json({ user_id: req.params.id });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
  res.status(204).send();
});

app.listen(3000);
