// Minimal Node.js Test Application
// This is a simple, secure Express app for testing purposes
// No real vulnerabilities - only synthetic test data

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Routes
app.get('/', (req, res) => {
  res.json({
    message: 'Test application running',
    version: '1.0.0'
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

app.get('/api/data', (req, res) => {
  const data = {
    items: [
      { id: 1, name: 'Item 1' },
      { id: 2, name: 'Item 2' }
    ]
  };
  res.json(data);
});

app.post('/api/echo', (req, res) => {
  console.log('Received echo request');
  res.json({ echo: req.body });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server (only if not in test mode)
if (require.main === module) {
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`Test app listening on http://127.0.0.1:${PORT}`);
  });
}

module.exports = app;
