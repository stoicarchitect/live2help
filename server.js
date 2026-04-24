import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = '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';

app.post('/api/claude', async (req, res) => {
  try {
    console.log('Received request:', req.body);
    
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();
    console.log('API Response status:', response.status);
    
    res.status(response.status).json(data);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({ status: 'API Server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
