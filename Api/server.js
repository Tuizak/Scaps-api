// server.js
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// ======= Config Stripe / Env
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const FORCE_3DS = (process.env.FORCE_3DS || '').toLowerCase() === 'true';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ======= DB
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectTimeout: 10000,
    acquireTimeout: 10000,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

pool.getConnection((err, connection) => {
    if (err) { console.error('Error connecting to DB:', err); return; }
    if (connection) connection.release();
    console.log('✅ MySQL connected');
});

function queryAsync(sql, params) {
    return new Promise((resolve, reject) => {
        pool.query(sql, params, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
}

app.use((req, res, next) => { req.db = pool; next(); });

// ======= Middleware
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ======= Multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Solo se permiten imágenes'), false);
    }
});

// ======= Auth
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto_scaps';
function generarToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }); }
function verificarToken(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No autorizado' });
    try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
    catch { return res.status(401).json({ error: 'Token inválido' }); }
}

// ======= Endpoints

// -------- Proveedores
app.get('/api/proveedores', (req, res) => {
    const sql = 'SELECT * FROM Proveedores';
    req.db.query(sql, (err, results) => {
        if (err) { console.error(err); return res.status(500).send(err.message); }
        res.json(results);
    });
});

// -------- Categorias
app.get('/api/categorias', (req, res) => {
    const sql = 'SELECT * FROM Categorias';
    req.db.query(sql, (err, results) => {
        if (err) { console.error(err); return res.status(500).send(err.message); }
        res.json(results);
    });
});

// -------- Productos
app.get('/api/productos', (req, res) => {
    const sql = 'SELECT * FROM Productos';
    req.db.query(sql, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

app.get('/api/productos/:id', (req, res) => {
    const sql = 'SELECT * FROM Productos WHERE id=?';
    req.db.query(sql, [req.params.id], (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

app.post('/api/productos', upload.single('foto'), (req, res) => {
    const { nombre, precio, stock, descripcion, categoria_id, proveedor_id } = req.body;
    const foto = req.file ? req.file.filename : null;
    const sql = 'INSERT INTO Productos (nombre, descripcion, precio, stock, categoria_id, proveedor_id, foto) VALUES (?,?,?,?,?,?,?)';
    req.db.query(sql, [nombre, descripcion, precio, stock, categoria_id, proveedor_id, foto], (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.status(201).json(result);
    });
});

app.put('/api/productos/:id', upload.single('foto'), (req, res) => {
    const { id } = req.params;
    const { nombre, precio, stock, descripcion, categoria_id, proveedor_id } = req.body;
    const foto = req.file ? req.file.filename : null;

    const updateFields = [];
    const updateValues = [];
    if (nombre) { updateFields.push('nombre=?'); updateValues.push(nombre); }
    if (precio) { updateFields.push('precio=?'); updateValues.push(precio); }
    if (stock) { updateFields.push('stock=?'); updateValues.push(stock); }
    if (descripcion) { updateFields.push('descripcion=?'); updateValues.push(descripcion); }
    if (categoria_id) { updateFields.push('categoria_id=?'); updateValues.push(categoria_id); }
    if (proveedor_id) { updateFields.push('proveedor_id=?'); updateValues.push(proveedor_id); }
    if (foto) { updateFields.push('foto=?'); updateValues.push(foto); }
    if (!updateFields.length) return res.status(400).send('Nada que actualizar');
    updateValues.push(id);

    const sql = `UPDATE Productos SET ${updateFields.join(', ')} WHERE id=?`;
    req.db.query(sql, updateValues, (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.json(result);
    });
});

app.delete('/api/productos/:id', (req, res) => {
    const sql = 'DELETE FROM Productos WHERE id=?';
    req.db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.json(result);
    });
});

app.get('/api/productos/categoria/:categoria_id', (req, res) => {
    const sql = 'SELECT * FROM Productos WHERE categoria_id=?';
    req.db.query(sql, [req.params.categoria_id], (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

// -------- Estadísticas
app.get('/api/statistics/proveedores', (req, res) => {
    const sql = 'SELECT COUNT(*) AS total FROM Proveedores';
    req.db.query(sql, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results[0].total);
    });
});

app.get('/api/statistics/productos-categoria', (req, res) => {
    const sql = `
        SELECT Categorias.nombre AS categoria, COUNT(Productos.id) AS total
        FROM Productos
        JOIN Categorias ON Productos.categoria_id = Categorias.id
        GROUP BY Categorias.nombre
    `;
    req.db.query(sql, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

// -------- Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { usuario, password } = req.body;
        if (!usuario || !password) return res.status(400).json({ error: 'Faltan datos' });
        const rows = await queryAsync('SELECT id, Usuario, password FROM admin WHERE Usuario=? LIMIT 1', [usuario]);
        if (!rows.length || rows[0].password !== password) return res.status(401).json({ error: 'Credenciales inválidas' });
        const row = rows[0];
        const token = generarToken({ id: row.id, usuario: row.Usuario, rol: 'admin' });
        res.json({ id: row.id, usuario: row.Usuario, rol: 'admin', token });
    } catch (e) { res.status(500).json({ error: 'Error interno' }); }
});

// -------- Gorras
app.get('/api/gorras', async (req, res) => {
    try { const rows = await queryAsync('SELECT id, Nombre, precio, imagen, descripcion FROM gorras'); res.json(rows); }
    catch (e) { res.status(500).json({ error: 'Error al obtener gorras' }); }
});

app.get('/api/gorras/:id', async (req, res) => {
    try {
        const id = Number(req.params.id); if (!id) return res.status(400).json({ error: 'ID inválido' });
        const rows = await queryAsync('SELECT * FROM gorras WHERE id=?', [id]); if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
        res.json(rows[0]);
    } catch (e) { res.status(500).json({ error: 'Error interno' }); }
});

app.post('/api/gorras', verificarToken, upload.single('imagen'), async (req, res) => {
    try {
        const { Nombre, precio, descripcion } = req.body;
        const imagen = req.file ? `/uploads/${req.file.filename}` : null;
        if (!Nombre || !precio || !descripcion) return res.status(400).json({ error: 'Faltan datos' });
        const result = await queryAsync('INSERT INTO gorras (Nombre, precio, imagen, descripcion) VALUES (?,?,?,?)', [Nombre, precio, imagen, descripcion]);
        res.status(201).json({ message: 'Gorra creada', id: result.insertId });
    } catch (e) { res.status(500).json({ error: 'Error al crear gorra' }); }
});

app.put('/api/gorras/:id', verificarToken, upload.single('imagen'), async (req, res) => {
    try {
        const { id } = req.params;
        const { Nombre, precio, descripcion } = req.body;
        const imagen = req.file ? `/uploads/${req.file.filename}` : (req.body.imagen ?? null);
        const campos = []; const valores = [];
        if (Nombre!==undefined){ campos.push('Nombre=?'); valores.push(Nombre); }
        if (precio!==undefined){ campos.push('precio=?'); valores.push(precio); }
        if (descripcion!==undefined){ campos.push('descripcion=?'); valores.push(descripcion); }
        if (imagen!==undefined){ campos.push('imagen=?'); valores.push(imagen); }
        if (!campos.length) return res.status(400).json({ error: 'Nada que actualizar' });
        valores.push(id);
        await queryAsync(`UPDATE gorras SET ${campos.join(', ')} WHERE id=?`, valores);
        res.json({ message: 'Gorra actualizada', id });
    } catch (e) { res.status(500).json({ error: 'Error al actualizar' }); }
});

app.delete('/api/gorras/:id', verificarToken, async (req, res) => {
    try { const { id } = req.params; await queryAsync('DELETE FROM gorras WHERE id=?', [id]); res.json({ message: 'Gorra eliminada', id }); }
    catch (e) { res.status(500).json({ error: 'Error al eliminar' }); }
});

// -------- Stripe Checkout
app.post('/api/payments/checkout-session', async (req, res) => {
    try {
        if (!STRIPE_SECRET_KEY || !/^sk_/.test(STRIPE_SECRET_KEY)) return res.status(400).json({ error: 'Stripe no configurado' });
        const { productId, name, amount, currency, success_url, cancel_url } = req.body;
        let finalName = name; let finalAmount = amount;
        if ((!finalName || !finalAmount) && productId) {
            const rows = await queryAsync('SELECT Nombre, precio FROM gorras WHERE id=? LIMIT 1', [productId]);
            if (!rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
            finalName = finalName || rows[0].Nombre;
            finalAmount = Math.round(Number(rows[0].precio) * 100);
        }
        if (!finalName || !finalAmount) return res.status(400).json({ error: 'Faltan datos' });
        const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            payment_method_types: ['card'],
            payment_method_options: { card: { request_three_d_secure: FORCE_3DS ? 'any' : 'automatic' } },
            line_items: [{ price_data: { currency: currency || 'mxn', product_data: { name: finalName }, unit_amount: Number(finalAmount) }, quantity: 1 }],
            success_url: success_url || 'https://example.com/success',
            cancel_url: cancel_url || 'https://example.com/cancel',
        });
        res.json({ url: session.url });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Error al crear sesión' }); }
});

// -------- Stripe Webhook opcional
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(400).send('Webhook Stripe no configurado');
    const sig = req.headers['stripe-signature'];
    let event;
    try { event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET); }
    catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
    res.json({ received: true });
});

// ======= Start Server
app.listen(port, () => console.log(`API running on port ${port}`));
