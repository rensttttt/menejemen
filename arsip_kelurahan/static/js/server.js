const express = require('express');
const session = require('express-session');
const svgCaptcha = require('svg-captcha');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: 'rahasia-ctf-123', // ganti dengan key aman
  resave: false,
  saveUninitialized: true
}));

// Route untuk menampilkan captcha sebagai gambar
app.get('/captcha', (req, res) => {
  const captcha = svgCaptcha.create({ noise: 2, background: '#f2f2f2' });
  req.session.captcha = captcha.text;
  res.type('svg');
  res.status(200).send(captcha.data);
});

// Contoh route register
app.post('/register', (req, res) => {
  const { captcha, username, password } = req.body;

  if (!captcha || captcha.toLowerCase() !== req.session.captcha.toLowerCase()) {
    return res.status(400).json({ success: false, message: 'Captcha tidak cocok' });
  }

  // Lanjutkan proses simpan user
  return res.json({ success: true });
});

app.listen(3000, () => {
  console.log('Server jalan di http://localhost:3000');
});
