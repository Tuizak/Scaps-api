const express = require('express');
const path = require('path');
const cors = require('cors');
const mysql = require('mysql');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

// ====== Variables de entorno (Render las maneja desde Dashboard)
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000; // ✅ Render necesita process.env.PORT

// ======= Config Stripe / Env
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto_scaps';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const FORCE_3DS = (process.env.FORCE_3DS || '').toLowerCase() === 'true';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ======= DB
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

// Conexión inicial
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Error al conectar a MySQL:', err);
    return;
  }
  if (connection) connection.release();
  console.log('✅ Conexión MySQL OK!');
});

// ======= Helper para usar query con promesas
function queryAsync(sql, params) {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}

// Middleware para agregar DB a req
app.use((req, res, next) => {
  req.db = pool;
  next();
});

// ======= Multer (⚠️ en Render los archivos en /uploads se borran cuando reinicia el server)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + (file.originalname || 'img')),
});
const upload = multer({ storage });

// ======= Middlewares
app.use(cors());

// Stripe webhook necesita raw body, lo ponemos ANTES de express.json
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(400).send('Stripe webhook no configurado');
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const productId = Number(session?.metadata?.productId || 0) || null;
        await queryAsync(
          'INSERT INTO pagos (stripe_session_id, stripe_payment_intent, product_id, amount, currency, status) VALUES (?,?,?,?,?,?)',
          [session.id, session.payment_intent, productId, session.amount_total, session.currency || 'mxn', 'paid']
        );
        break;
      }
      case 'checkout.session.expired': {
        const session = event.data.object;
        await queryAsync(
          'INSERT INTO pagos (stripe_session_id, stripe_payment_intent, product_id, amount, currency, status) VALUES (?,?,?,?,?,?)',
          [session.id, session.payment_intent || null, null, session.amount_total || null, session.currency || 'mxn', 'expired']
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
  } catch (outerErr) {
    console.error('Webhook fatal:', outerErr);
    res.status(500).send('Error de servidor en webhook');
  }
});

// Ahora sí el resto del body parser para todo lo demás
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ======= Helpers Auth
function generarToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}
function verificarToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Token inválido' }); }
}

// ======= LOGIN ADMIN
app.post('/api/admin/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Faltan datos' });

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

// ======= Endpoints Gorras
app.get('/api/gorras', async (req, res) => {
  try {
    const rows = await queryAsync('SELECT id, Nombre, precio, imagen, descripcion FROM gorras');
    res.json(rows);
  } catch (e) {
    console.error('GET /api/gorras error:', e);
    res.status(500).json({ error: 'Error al obtener gorras' });
  }
});

app.get('/api/gorras/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'ID inválido' });
    const rows = await queryAsync('SELECT id, Nombre, precio, descripcion, imagen FROM gorras WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json(rows[0]);
  } catch (e) {
    console.error('GET /api/gorras/:id error:', e);
    res.status(500).json({ error: 'Error interno al consultar el producto', detail: e.message });
  }
});

app.post('/api/gorras', verificarToken, upload.single('imagen'), async (req, res) => {
  try {
    const { Nombre, precio, descripcion } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : null;
    if (!Nombre || !precio || !descripcion) return res.status(400).json({ error: 'Faltan datos' });

    const result = await queryAsync('INSERT INTO gorras (Nombre, precio, imagen, descripcion) VALUES (?,?,?,?)', [Nombre, precio, imagen, descripcion]);
    res.status(201).json({
      message: 'Gorra creada correctamente',
      id: result.insertId,
      gorra: { id: result.insertId, Nombre, precio, imagen, descripcion }
    });
  } catch (e) {
    console.error('POST /api/gorras error:', e);
    res.status(500).json({ error: 'Error al crear gorra' });
  }
});

app.put('/api/gorras/:id', verificarToken, upload.single('imagen'), async (req, res) => {
  try {
    const { id } = req.params;
    const { Nombre, precio, descripcion } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : (req.body.imagen ?? null);

    const campos = [];
    const valores = [];
    if (Nombre !== undefined)      { campos.push('Nombre=?');      valores.push(Nombre); }
    if (precio !== undefined)      { campos.push('precio=?');      valores.push(precio); }
    if (descripcion !== undefined) { campos.push('descripcion=?'); valores.push(descripcion); }
    if (imagen !== undefined)      { campos.push('imagen=?');      valores.push(imagen); }
    if (!campos.length) return res.status(400).json({ error: 'Nada que actualizar' });

    valores.push(id);
    await queryAsync(`UPDATE gorras SET ${campos.join(', ')} WHERE id = ?`, valores);
    res.json({ message: 'Gorra actualizada correctamente', id });
  } catch (e) {
    console.error('PUT /api/gorras/:id error:', e);
    res.status(500).json({ error: 'Error al actualizar' });
  }
});

app.delete('/api/gorras/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    await queryAsync('DELETE FROM gorras WHERE id = ?', [id]);
    res.json({ message: 'Gorra eliminada correctamente', id });
  } catch (e) {
    console.error('DELETE /api/gorras/:id error:', e);
    res.status(500).json({ error: 'Error al eliminar' });
  }
});

// ===== Stripe Checkout
app.post('/api/payments/checkout-session', async (req, res) => {
  try {
    if (!STRIPE_SECRET_KEY || !/^sk_/.test(STRIPE_SECRET_KEY)) {
      return res.status(400).json({ error: 'STRIPE_SECRET_KEY no configurada o inválida' });
    }
    const stripe = new Stripe(STRIPE_SECRET_KEY);
    const force3ds = String(process.env.FORCE_3DS || '').toLowerCase() === 'true';
    const { productId, name, amount, currency, success_url, cancel_url } = req.body;

    let finalName = name;
    let finalAmount = amount;

    if ((!finalName || !finalAmount) && productId) {
      const rows = await queryAsync('SELECT Nombre, precio FROM gorras WHERE id = ? LIMIT 1', [productId]);
      if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
      finalName = finalName || rows[0].Nombre || 'Producto';
      finalAmount = Math.round(Number(rows[0].precio) * 100);
    }

    if (!finalName || !finalAmount) return res.status(400).json({ error: 'Faltan datos para crear el pago' });

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      payment_method_options: { card: { request_three_d_secure: force3ds ? 'any' : 'automatic' } },
      line_items: [{
        price_data: { currency: currency || 'mxn', product_data: { name: finalName }, unit_amount: finalAmount },
        quantity: 1
      }],
      payment_intent_data: { metadata: { productId: String(productId || '') } },
      success_url: success_url || 'http://localhost:5173/postpago?status=success',
      cancel_url:  cancel_url  || 'http://localhost:5173/'
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error('checkout-session error:', err?.type || err?.name, err?.message);
    return res.status(500).json({ error: 'No se pudo crear la sesión de pago', detail: err?.message });
  }
});

// ======= Arranque
app.listen(port, () => console.log(`🚀 API corriendo en http://localhost:${port}`));
