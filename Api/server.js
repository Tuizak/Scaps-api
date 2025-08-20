const express = require('express');
const path = require('path');
const cors = require('cors');
const mysql = require('mysql');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

// Variables de entorno (Render las inyecta automáticamente)
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto_scaps';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const FORCE_3DS = (process.env.FORCE_3DS || '').toLowerCase() === 'true';

const app = express();

// ⚡ IMPORTANTE: json global excepto en Stripe webhook
app.use((req, res, next) => {
  if (req.originalUrl === '/api/payments/webhook') {
    next(); // Stripe necesita raw body
  } else {
    express.json()(req, res, next);
  }
});

app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ======= DB (usa variables de entorno de Render)
const dbConfig = {
  host: process.env.DB_HOST || 'srv577.hstgr.io',
  user: process.env.DB_USER || 'u990150337_scaps',
  password: process.env.DB_PASSWORD || 'Scaps1234',
  database: process.env.DB_NAME || 'u990150337_scaps',
  connectTimeout: 10000,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error DB:', err);
    return;
  }
  if (connection) connection.release();
  console.log('✅ Conexión MySQL OK!');
});

function queryAsync(sql, params) {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}

// ======= Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + (file.originalname || 'img')),
});
const upload = multer({ storage });

// ======= Stripe Webhook
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!STRIPE_SECRET_KEY || !STRIPE_WEBHOOK_SECRET) return res.status(400).send('Stripe no configurado');
    const stripe = new Stripe(STRIPE_SECRET_KEY);
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);

    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        await queryAsync(
          'INSERT INTO pagos (stripe_session_id, stripe_payment_intent, product_id, amount, currency, status) VALUES (?,?,?,?,?,?)',
          [s.id, s.payment_intent, Number(s?.metadata?.productId) || null, s.amount_total, s.currency || 'mxn', 'paid']
        );
        break;
      }
      case 'checkout.session.expired': {
        const s = event.data.object;
        await queryAsync(
          'INSERT INTO pagos (stripe_session_id, stripe_payment_intent, product_id, amount, currency, status) VALUES (?,?,?,?,?,?)',
          [s.id, s.payment_intent || null, null, s.amount_total || null, s.currency || 'mxn', 'expired']
        );
        break;
      }
      case 'payment_intent.payment_failed': {
        const pi = event.data.object;
        await queryAsync(
          'INSERT INTO pagos (stripe_session_id, stripe_payment_intent, product_id, amount, currency, status) VALUES (?,?,?,?,?,?)',
          [null, pi.id, Number(pi.metadata?.productId) || null, pi.amount || null, pi.currency || 'mxn', 'failed']
        );
        break;
      }
      default: break;
    }
    res.json({ received: true });
  } catch (err) {
    console.error('❌ Webhook error:', err.message);
    res.status(500).send('Error webhook');
  }
});

// ======= Helpers Auth
function generarToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }); }
function verificarToken(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Token inválido' }); }
}

// ======= LOGIN ADMIN
app.post('/api/admin/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const rows = await queryAsync('SELECT id, Usuario, password FROM admin WHERE Usuario = ? LIMIT 1', [usuario]);
    if (!rows.length || rows[0].password !== password)
      return res.status(401).json({ error: 'Credenciales inválidas' });

    const row = rows[0];
    const token = generarToken({ id: row.id, usuario: row.Usuario, rol: 'admin' });
    res.json({ id: row.id, usuario: row.Usuario, rol: 'admin', token });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ======= CRUD Gorras
app.get('/api/gorras', async (_, res) => {
  try { res.json(await queryAsync('SELECT id, Nombre, precio, imagen, descripcion FROM gorras')); }
  catch (e) { res.status(500).json({ error: 'Error al obtener gorras' }); }
});

app.get('/api/gorras/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const rows = await queryAsync('SELECT * FROM gorras WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Error interno' }); }
});

app.post('/api/gorras', verificarToken, upload.single('imagen'), async (req, res) => {
  try {
    const { Nombre, precio, descripcion } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await queryAsync(
      'INSERT INTO gorras (Nombre, precio, imagen, descripcion) VALUES (?,?,?,?)',
      [Nombre, precio, imagen, descripcion]
    );
    res.status(201).json({ id: result.insertId });
  } catch (e) { res.status(500).json({ error: 'Error al crear gorra' }); }
});

app.put('/api/gorras/:id', verificarToken, upload.single('imagen'), async (req, res) => {
  try {
    const { id } = req.params;
    const { Nombre, precio, descripcion } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : req.body.imagen || null;

    const campos = []; const valores = [];
    if (Nombre) { campos.push('Nombre=?'); valores.push(Nombre); }
    if (precio) { campos.push('precio=?'); valores.push(precio); }
    if (descripcion) { campos.push('descripcion=?'); valores.push(descripcion); }
    if (imagen) { campos.push('imagen=?'); valores.push(imagen); }
    valores.push(id);

    await queryAsync(`UPDATE gorras SET ${campos.join(', ')} WHERE id=?`, valores);
    res.json({ message: 'Actualizado' });
  } catch (e) { res.status(500).json({ error: 'Error al actualizar' }); }
});

app.delete('/api/gorras/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    await queryAsync('DELETE FROM gorras WHERE id = ?', [id]);
    res.json({ message: 'Eliminado' });
  } catch (e) { res.status(500).json({ error: 'Error al eliminar' }); }
});

// ======= Checkout Stripe
app.post('/api/payments/checkout-session', async (req, res) => {
  try {
    if (!STRIPE_SECRET_KEY) return res.status(400).json({ error: 'Stripe no configurado' });
    const stripe = new Stripe(STRIPE_SECRET_KEY);
    const { productId, name, amount, currency, success_url, cancel_url } = req.body;

    let finalName = name, finalAmount = amount;
    if ((!finalName || !finalAmount) && productId) {
      const rows = await queryAsync('SELECT Nombre, precio FROM gorras WHERE id = ? LIMIT 1', [productId]);
      if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
      finalName = rows[0].Nombre;
      finalAmount = Math.round(Number(rows[0].precio) * 100);
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      payment_method_options: { card: { request_three_d_secure: FORCE_3DS ? 'any' : 'automatic' } },
      line_items: [{
        price_data: { currency: currency || 'mxn', product_data: { name: finalName }, unit_amount: finalAmount },
        quantity: 1
      }],
      payment_intent_data: { metadata: { productId: String(productId || '') } },
      success_url: success_url || 'https://tu-frontend.com/postpago?status=success',
      cancel_url: cancel_url || 'https://tu-frontend.com/'
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('❌ checkout-session error:', err.message);
    res.status(500).json({ error: 'No se pudo crear la sesión' });
  }
});

// ======= Arranque
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 API corriendo en puerto ${PORT}`));
