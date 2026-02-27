const express = require('express');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(6),
        code_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        paypal_transaction_id VARCHAR(255),
        plan VARCHAR(50),
        amount DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Database tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}
initDB();

// Nodemailer transporter (Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Generate 6-digit code
function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Send verification email
async function sendVerificationEmail(email, code) {
  const mailOptions = {
    from: `"Facts Search" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: '🔍 Facts Search - Verify Your Email',
    html: `
      <div style="font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px 30px; background: linear-gradient(135deg, #0c1929, #1a365d); border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <div style="font-size: 50px;">🔍</div>
          <h1 style="color: white; font-size: 24px; margin: 10px 0 5px;">Facts Search</h1>
          <p style="color: rgba(255,255,255,0.6); font-size: 14px;">Email Verification</p>
        </div>
        <div style="background: white; border-radius: 12px; padding: 30px; text-align: center;">
          <p style="color: #64748b; font-size: 15px; margin-bottom: 20px;">Your verification code is:</p>
          <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1a365d; background: #f1f5f9; padding: 20px; border-radius: 10px; margin-bottom: 20px;">${code}</div>
          <p style="color: #94a3b8; font-size: 13px;">This code expires in <strong>10 minutes</strong>.</p>
          <p style="color: #94a3b8; font-size: 13px; margin-top: 10px;">If you didn't request this, please ignore this email.</p>
        </div>
        <p style="text-align: center; color: rgba(255,255,255,0.4); font-size: 12px; margin-top: 20px;">Built by Office Soft Solutions</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Document Data
const US_CONSTITUTION = {
  preamble: "We the People of the United States, in Order to form a more perfect Union, establish Justice, insure domestic Tranquility, provide for the common defence, promote the general Welfare, and secure the Blessings of Liberty to ourselves and our Posterity, do ordain and establish this Constitution for the United States of America.",
  amendments: {
    1: { title: "Freedom of Religion, Speech, Press", year: 1791, text: "Congress shall make no law respecting an establishment of religion, or prohibiting the free exercise thereof; or abridging the freedom of speech, or of the press; or the right of the people peaceably to assemble, and to petition the Government for a redress of grievances." },
    2: { title: "Right to Bear Arms", year: 1791, text: "A well regulated Militia, being necessary to the security of a free State, the right of the people to keep and bear Arms, shall not be infringed." },
    4: { title: "Search and Seizure", year: 1791, text: "The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated." },
    5: { title: "Rights of the Accused", year: 1791, text: "No person shall be held to answer for a capital crime without indictment; nor be subject to double jeopardy; nor compelled to self-incrimination; nor deprived of life, liberty, or property without due process." },
    13: { title: "Abolition of Slavery", year: 1865, text: "Neither slavery nor involuntary servitude shall exist within the United States." },
    19: { title: "Women's Suffrage", year: 1920, text: "The right to vote shall not be denied on account of sex." }
  }
};

const UN_HUMAN_RIGHTS = {
  adopted: "December 10, 1948",
  articles: {
    1: "All human beings are born free and equal in dignity and rights.",
    3: "Everyone has the right to life, liberty and security of person.",
    4: "No one shall be held in slavery or servitude.",
    5: "No one shall be subjected to torture or cruel treatment.",
    18: "Everyone has the right to freedom of thought, conscience and religion.",
    19: "Everyone has the right to freedom of opinion and expression.",
    26: "Everyone has the right to education."
  }
};

// ==================== API ROUTES ====================

// Check if email is verified (no code sent)
app.post('/api/check-email', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  const cleanEmail = email.toLowerCase().trim();

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [cleanEmail]);

    if (result.rows.length > 0 && result.rows[0].verified) {
      // Already verified — update last login
      await pool.query('UPDATE users SET last_login = NOW() WHERE email = $1', [cleanEmail]);
      return res.json({ verified: true, email: cleanEmail });
    }

    // Not found or not verified
    res.json({ verified: false, email: cleanEmail });
  } catch (err) {
    console.error('Check email error:', err.message);
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// Send verification code (only for new/unverified users)
app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  try {
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [cleanEmail]);

    if (existing.rows.length > 0) {
      // Update code for existing user
      await pool.query(
        'UPDATE users SET verification_code = $1, code_expires_at = $2 WHERE email = $3',
        [code, expiresAt, cleanEmail]
      );
    } else {
      // New user
      await pool.query(
        'INSERT INTO users (email, verification_code, code_expires_at) VALUES ($1, $2, $3)',
        [cleanEmail, code, expiresAt]
      );
    }

    await sendVerificationEmail(cleanEmail, code);
    res.json({ success: true, message: 'Verification code sent', email: cleanEmail });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
  }
});

// Verify code
app.post('/api/verify', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ error: 'Email and code required' });
  }

  const cleanEmail = email.toLowerCase().trim();

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND verification_code = $2',
      [cleanEmail, code.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    const user = result.rows[0];

    if (new Date() > new Date(user.code_expires_at)) {
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });
    }

    await pool.query(
      'UPDATE users SET verified = TRUE, verification_code = NULL, code_expires_at = NULL, last_login = NOW() WHERE email = $1',
      [cleanEmail]
    );

    res.json({ success: true, email: cleanEmail, verified: true });
  } catch (err) {
    console.error('Verify error:', err.message);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
});

// Resend code
app.post('/api/resend-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const cleanEmail = email.toLowerCase().trim();
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [cleanEmail]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found. Please login first.' });
    }

    await pool.query(
      'UPDATE users SET verification_code = $1, code_expires_at = $2 WHERE email = $3',
      [code, expiresAt, cleanEmail]
    );

    await sendVerificationEmail(cleanEmail, code);
    res.json({ success: true, message: 'New code sent' });
  } catch (err) {
    console.error('Resend error:', err.message);
    res.status(500).json({ error: 'Failed to resend code' });
  }
});

// Admin: view all users
app.get('/api/admin/users', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const result = await pool.query('SELECT id, email, verified, created_at, last_login FROM users ORDER BY created_at DESC');
    res.json({ users: result.rows, total: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ==================== DOCUMENT SEARCH ROUTES ====================

app.get('/api/sources', (req, res) => {
  res.json({
    sources: [
      { id: 'cia-factbook', name: 'CIA World Factbook', icon: '🌍', description: 'Country information worldwide' },
      { id: 'us-constitution', name: 'US Constitution', icon: '📜', description: 'Articles and Amendments' },
      { id: 'declaration', name: 'Declaration of Independence', icon: '🗽', description: 'US founding document' },
      { id: 'un-rights', name: 'UN Human Rights', icon: '🕊️', description: '30 Articles of Human Rights' },
      { id: 'world-bank', name: 'World Bank Data', icon: '📊', description: 'Economic indicators by country' },
      { id: 'gutenberg', name: 'Project Gutenberg', icon: '📚', description: '70,000+ free books' }
    ]
  });
});

app.get('/api/search/cia-factbook', async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'Query required' });
  try {
    const countrySlug = query.toLowerCase().trim().replace(/\s+/g, '-');
    const url = `https://www.cia.gov/the-world-factbook/countries/${countrySlug}/`;
    await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 });
    res.json({ success: true, data: { country: query, source: 'CIA World Factbook', source_url: url } });
  } catch (err) {
    res.status(404).json({ error: 'Country not found', suggestion: 'Try full country name (e.g., "Germany" not "DE")' });
  }
});

app.get('/api/search/us-constitution', (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'Query required' });
  const q = query.toLowerCase();
  const results = { source: 'US Constitution', matches: [] };
  if (q.includes('preamble') || q.includes('we the people')) {
    results.matches.push({ type: 'Preamble', content: US_CONSTITUTION.preamble });
  }
  for (const [num, amend] of Object.entries(US_CONSTITUTION.amendments)) {
    if (q.includes(num) || amend.text.toLowerCase().includes(q) || amend.title.toLowerCase().includes(q)) {
      results.matches.push({ type: `Amendment ${num}`, title: amend.title, year: amend.year, content: amend.text });
    }
  }
  if (results.matches.length === 0) {
    return res.status(404).json({ error: 'No matches', suggestion: 'Try: preamble, 1, 2, speech, arms, slavery' });
  }
  res.json({ success: true, data: results });
});

app.get('/api/search/declaration', (req, res) => {
  res.json({
    success: true,
    data: {
      source: 'Declaration of Independence', date: 'July 4, 1776',
      authors: 'Thomas Jefferson, Benjamin Franklin, John Adams',
      famous_quote: 'We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.',
      signers_count: 56,
      key_principles: ['All men are created equal', 'Unalienable rights: Life, Liberty, Pursuit of Happiness', 'Governments derive power from consent of the governed']
    }
  });
});

app.get('/api/search/un-rights', (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'Query required' });
  const q = query.toLowerCase();
  const results = { source: 'UN Human Rights Declaration', adopted: UN_HUMAN_RIGHTS.adopted, matches: [] };
  if (q.includes('all') || q.includes('list')) {
    results.all_articles = UN_HUMAN_RIGHTS.articles;
  } else {
    for (const [num, text] of Object.entries(UN_HUMAN_RIGHTS.articles)) {
      if (q.includes(num) || text.toLowerCase().includes(q)) {
        results.matches.push({ article: num, content: text });
      }
    }
  }
  if (results.matches.length === 0 && !results.all_articles) {
    return res.status(404).json({ error: 'No matches', suggestion: 'Try: 1, freedom, education, all' });
  }
  res.json({ success: true, data: results });
});

app.get('/api/search/world-bank', async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'Query required' });
  try {
    const url = `https://api.worldbank.org/v2/country/${encodeURIComponent(query)}?format=json`;
    const response = await axios.get(url, { timeout: 10000 });
    if (response.data && response.data[1] && response.data[1][0]) {
      const country = response.data[1][0];
      res.json({
        success: true,
        data: { source: 'World Bank', country: country.name, iso_code: country.id, capital: country.capitalCity || 'N/A', region: country.region?.value || 'N/A', income_level: country.incomeLevel?.value || 'N/A' }
      });
    } else {
      res.status(404).json({ error: 'Country not found', suggestion: 'Try country code: USA, GBR, IND, CHN' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

app.get('/api/search/gutenberg', async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).json({ error: 'Query required' });
  try {
    const url = `https://gutendex.com/books/?search=${encodeURIComponent(query)}`;
    const response = await axios.get(url, { timeout: 10000 });
    const books = response.data.results.slice(0, 10).map(book => ({
      id: book.id, title: book.title, authors: book.authors.map(a => a.name).join(', '), url: `https://www.gutenberg.org/ebooks/${book.id}`
    }));
    res.json({ success: true, data: { source: 'Project Gutenberg', total: response.data.count, books } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to search' });
  }
});

// Subscription
app.post('/api/subscription', async (req, res) => {
  const { email, paypal_transaction_id, plan, amount } = req.body;
  try {
    await pool.query(
      'INSERT INTO subscriptions (email, paypal_transaction_id, plan, amount) VALUES ($1, $2, $3, $4)',
      [email.toLowerCase().trim(), paypal_transaction_id, plan, amount]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save subscription' });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Facts Search running on port ${PORT}`);
});
