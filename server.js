require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const axios = require('axios');
const admin = require('firebase-admin');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const INFINITEPAY_API_BASE = process.env.INFINITEPAY_API_BASE || 'https://api.infinitepay.io';
const INFINITEPAY_HANDLE = (process.env.INFINITEPAY_HANDLE || '').trim();
const INFINITEPAY_REDIRECT_URL = (process.env.INFINITEPAY_REDIRECT_URL || '').trim();
const INFINITEPAY_WEBHOOK_URL = (process.env.INFINITEPAY_WEBHOOK_URL || '').trim();
const ORDER_HMAC_SECRET = (process.env.ORDER_HMAC_SECRET || '').trim();

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map(item => item.trim().toLowerCase())
  .filter(Boolean);

if (!INFINITEPAY_HANDLE) {
  throw new Error('INFINITEPAY_HANDLE nao configurada.');
}

if (!ORDER_HMAC_SECRET || ORDER_HMAC_SECRET.length < 24) {
  throw new Error('ORDER_HMAC_SECRET obrigatoria com no minimo 24 caracteres.');
}

initializeFirebaseAdmin();
const db = admin.firestore();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors({
  origin: resolveCorsOrigin(),
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'loja-zelp-infinitepay', timestamp: new Date().toISOString() });
});

app.post('/api/orders/create-checkout', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const payload = buildOrderPayload(req.body || {}, user);

    const checkoutData = await createInfinitePayCheckout(payload);

    const orderRecord = {
      ...payload,
      payment: {
        provider: 'infinitepay',
        handle: INFINITEPAY_HANDLE,
        amountCents: payload.amountCents,
        amountBRL: Number((payload.amountCents / 100).toFixed(2)),
        status: 'pending',
        paid: false,
        paidAtISO: null,
        receiptUrl: '',
        captureMethod: '',
        checkoutUrl: checkoutData.checkoutUrl,
        slug: checkoutData.slug || '',
        transactionNsu: checkoutData.transactionNsu || '',
        installments: null,
        lastCheckISO: null,
        rawCheckoutResponse: checkoutData.raw
      },
      chat: {
        unlocked: false,
        unlockedAtISO: null
      },
      integrity: {
        version: 'v1',
        digest: signIntegrity(payload),
        status: 'valid',
        lastVerifiedISO: payload.createdAtISO
      }
    };

    await db.collection('orders').doc(payload.orderId).set(orderRecord, { merge: false });

    res.json({
      success: true,
      orderId: payload.orderId,
      checkoutUrl: checkoutData.checkoutUrl,
      amountCents: payload.amountCents,
      amountBRL: Number((payload.amountCents / 100).toFixed(2)),
      paymentStatus: 'pending'
    });
  } catch (error) {
    console.error('[create-checkout] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao criar checkout.'
    });
  }
});

app.post('/api/payments/check', optionalAuth, async (req, res) => {
  try {
    const { order_nsu, orderId, slug, transaction_nsu, receipt_url } = req.body || {};
    const normalizedOrderId = normalizeOrderId(order_nsu || orderId);
    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'order_nsu/orderId e obrigatorio.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const orderDoc = await orderRef.get();
    if (!orderDoc.exists) {
      return res.status(404).json({ success: false, error: 'Pedido nao encontrado.' });
    }

    const order = orderDoc.data();
    ensureOrderAccess(req.user, order);
    await ensureIntegrityOrBlock(orderRef, order);

    const requestBody = {
      handle: INFINITEPAY_HANDLE,
      order_nsu: normalizedOrderId,
      slug: String(slug || order.payment?.slug || '').trim(),
      transaction_nsu: String(transaction_nsu || order.payment?.transactionNsu || '').trim()
    };

    if (!requestBody.slug || !requestBody.transaction_nsu) {
      return res.json({
        success: true,
        paid: Boolean(order.payment?.paid),
        amount: order.payment?.amountCents || 0,
        paid_amount: order.payment?.paidAmount || 0,
        installments: order.payment?.installments || null,
        capture_method: order.payment?.captureMethod || '',
        order_nsu: normalizedOrderId
      });
    }

    const paymentCheck = await callInfinitePay('/invoices/public/checkout/payment_check', requestBody);
    const paid = Boolean(paymentCheck && paymentCheck.paid);

    const nowISO = new Date().toISOString();
    const updates = {
      'payment.lastCheckISO': nowISO,
      'payment.slug': requestBody.slug || order.payment?.slug || '',
      'payment.transactionNsu': requestBody.transaction_nsu || order.payment?.transactionNsu || '',
      'payment.captureMethod': paymentCheck.capture_method || order.payment?.captureMethod || '',
      'payment.receiptUrl': receipt_url || order.payment?.receiptUrl || '',
      'payment.installments': Number.isFinite(Number(paymentCheck.installments)) ? Number(paymentCheck.installments) : (order.payment?.installments || null),
      'payment.paidAmount': Number.isFinite(Number(paymentCheck.paid_amount)) ? Number(paymentCheck.paid_amount) : (order.payment?.paidAmount || null),
      'payment.amount': Number.isFinite(Number(paymentCheck.amount)) ? Number(paymentCheck.amount) : (order.payment?.amount || null),
      'payment.status': paid ? 'paid' : 'pending',
      'payment.paid': paid,
      'integrity.lastVerifiedISO': nowISO,
      updatedAtISO: nowISO,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (paid) {
      updates['payment.paidAtISO'] = nowISO;
      updates['chat.unlocked'] = true;
      updates['chat.unlockedAtISO'] = nowISO;
    }

    await orderRef.set(updates, { merge: true });

    return res.json({
      success: true,
      paid,
      amount: paymentCheck.amount,
      paid_amount: paymentCheck.paid_amount,
      installments: paymentCheck.installments,
      capture_method: paymentCheck.capture_method,
      order_nsu: normalizedOrderId
    });
  } catch (error) {
    console.error('[payments-check] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao consultar pagamento.'
    });
  }
});

app.post('/api/orders/access-check', optionalAuth, async (req, res) => {
  try {
    const normalizedOrderId = normalizeOrderId(req.body?.orderId);
    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'orderId obrigatorio.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const orderDoc = await orderRef.get();
    if (!orderDoc.exists) {
      return res.status(404).json({ success: false, error: 'Pedido nao encontrado.' });
    }

    const order = orderDoc.data();
    ensureOrderAccess(req.user, order);
    await ensureIntegrityOrBlock(orderRef, order);

    const canOpenChat = Boolean(order.chat?.unlocked && order.payment?.paid);
    res.json({
      success: true,
      orderId: normalizedOrderId,
      canOpenChat,
      paid: Boolean(order.payment?.paid),
      paymentStatus: order.payment?.status || 'pending',
      integrityStatus: order.integrity?.status || 'unknown',
      checkoutUrl: order.payment?.checkoutUrl || ''
    });
  } catch (error) {
    console.error('[access-check] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao verificar acesso do pedido.'
    });
  }
});

app.post('/api/webhooks/infinitepay', async (req, res) => {
  try {
    const body = req.body || {};
    const normalizedOrderId = normalizeOrderId(body.order_nsu);

    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'order_nsu ausente no webhook.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const orderDoc = await orderRef.get();

    if (!orderDoc.exists) {
      return res.status(404).json({ success: false, error: 'Pedido nao encontrado para webhook.' });
    }

    const order = orderDoc.data();
    await ensureIntegrityOrBlock(orderRef, order);

    if (body.invoice_slug && order.payment?.slug && body.invoice_slug !== order.payment.slug) {
      return res.status(400).json({ success: false, error: 'invoice_slug divergente.' });
    }

    const amountFromWebhook = Number(body.amount);
    if (Number.isFinite(amountFromWebhook) && order.payment?.amountCents && amountFromWebhook !== order.payment.amountCents) {
      await orderRef.set({
        'integrity.status': 'tampered',
        'chat.unlocked': false,
        'payment.status': 'blocked',
        updatedAtISO: new Date().toISOString(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return res.status(400).json({ success: false, error: 'Valor divergente detectado.' });
    }

    const nowISO = new Date().toISOString();
    await orderRef.set({
      'payment.status': 'paid',
      'payment.paid': true,
      'payment.paidAtISO': nowISO,
      'payment.receiptUrl': body.receipt_url || order.payment?.receiptUrl || '',
      'payment.captureMethod': body.capture_method || order.payment?.captureMethod || '',
      'payment.transactionNsu': body.transaction_nsu || order.payment?.transactionNsu || '',
      'payment.slug': body.invoice_slug || order.payment?.slug || '',
      'payment.installments': Number.isFinite(Number(body.installments)) ? Number(body.installments) : (order.payment?.installments || null),
      'payment.paidAmount': Number.isFinite(Number(body.paid_amount)) ? Number(body.paid_amount) : (order.payment?.paidAmount || null),
      'chat.unlocked': true,
      'chat.unlockedAtISO': nowISO,
      'integrity.lastVerifiedISO': nowISO,
      updatedAtISO: nowISO,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('[webhook] erro:', error);
    return res.status(400).json({ success: false, error: 'Nao foi possivel processar o webhook.' });
  }
});

app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});

function initializeFirebaseAdmin() {
  if (admin.apps.length > 0) {
    return;
  }

  const base64 = process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64;
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (base64) {
    const decoded = Buffer.from(base64, 'base64').toString('utf8');
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(decoded)) });
    return;
  }

  if (rawJson) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(rawJson)) });
    return;
  }

  admin.initializeApp({ credential: admin.credential.applicationDefault() });
}

function resolveCorsOrigin() {
  const value = (process.env.FRONTEND_ORIGIN || '*').trim();
  if (!value || value === '*') {
    return true;
  }

  const allowed = value.split(',').map(item => item.trim()).filter(Boolean);
  return (origin, callback) => {
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Origin nao permitida no CORS'));
  };
}

async function optionalAuth(req, res, next) {
  const authHeader = String(req.headers.authorization || '').trim();
  if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
    req.user = null;
    return next();
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    req.user = null;
    return next();
  }

  try {
    req.user = await admin.auth().verifyIdToken(token);
    return next();
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Token invalido.' });
  }
}

async function requireAuth(req, res, next) {
  return optionalAuth(req, res, () => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Login obrigatorio para criar pedido.' });
    }
    return next();
  });
}

function buildOrderPayload(body, user) {
  const createdAtISO = new Date().toISOString();
  const planLevel = sanitizeString(body.planLevel, 32) || 'Basic';
  const extras = Array.isArray(body.extras)
    ? body.extras.map(item => sanitizeString(item, 60)).filter(Boolean).slice(0, 25)
    : [];
  const projectType = sanitizeString(body.projectType, 90) || inferProjectType(planLevel, extras);
  const deadline = sanitizeString(body.deadline, 40);
  const pages = Number(body.pages || 1);

  const budget = calculateBudget(projectType || 'Landing Page', pages, extras.length, deadline || '3-4 semanas', planLevel);
  const amountCents = Math.max(100, Math.round(budget.min * 100));

  const orderId = normalizeOrderId(body.orderId) || generateOrderId();

  return {
    orderId,
    userId: user.uid,
    userName: sanitizeString(body.projectName || user.name || user.email || 'Cliente', 120),
    userEmail: sanitizeEmail(body.projectEmail || user.email || ''),
    projectName: sanitizeString(body.projectName, 120),
    projectType: projectType || 'Landing Page',
    businessNiche: sanitizeString(body.businessNiche, 100),
    businessObjective: sanitizeString(body.businessObjective, 2000),
    references: sanitizeString(body.references, 2000),
    deadline: deadline || '3-4 semanas',
    planLevel,
    pages: Number.isFinite(pages) && pages > 0 ? pages : 1,
    extras,
    budget: formatBudget(budget.min, budget.max),
    budgetMin: budget.min,
    budgetMax: budget.max,
    amountCents,
    status: 'Pedido recebido',
    adminMessage: '',
    createdAtISO,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };
}

async function createInfinitePayCheckout(order) {
  const checkoutLabel = order.extras && order.extras.length
    ? `${order.planLevel} - ${order.extras.join(', ')}`
    : `${order.planLevel} - ${order.projectType}`;

  const checkoutPayload = {
    handle: INFINITEPAY_HANDLE,
    items: [
      {
        quantity: 1,
        price: order.amountCents,
        description: `Projeto ${checkoutLabel}`.slice(0, 120)
      }
    ],
    order_nsu: order.orderId
  };
  checkoutPayload.itens = checkoutPayload.items;

  if (INFINITEPAY_REDIRECT_URL) {
    checkoutPayload.redirect_url = INFINITEPAY_REDIRECT_URL;
  }

  if (INFINITEPAY_WEBHOOK_URL) {
    checkoutPayload.webhook_url = INFINITEPAY_WEBHOOK_URL;
  }

  if (order.userName || order.userEmail) {
    checkoutPayload.customer = {
      name: order.userName || undefined,
      email: order.userEmail || undefined
    };
  }

  const response = await callInfinitePay('/invoices/public/checkout/links', checkoutPayload);
  const checkoutUrl = extractCheckoutUrl(response);

  if (!checkoutUrl) {
    const error = new Error('InfinitePay nao retornou URL de checkout.');
    error.statusCode = 502;
    error.publicMessage = 'Nao foi possivel gerar o checkout agora. Tente novamente.';
    throw error;
  }

  return {
    checkoutUrl,
    slug: extractFirstString(response, ['slug', 'invoice_slug', 'invoice.slug', 'data.slug']),
    transactionNsu: extractFirstString(response, ['transaction_nsu', 'transactionNsu', 'data.transaction_nsu']),
    raw: response
  };
}

function extractCheckoutUrl(payload) {
  if (!payload || typeof payload !== 'object') {
    return '';
  }

  const candidates = [
    'checkout_url',
    'payment_url',
    'payment_link',
    'link',
    'url',
    'data.checkout_url',
    'data.payment_url',
    'invoice.checkout_url',
    'invoice.url'
  ];

  for (const key of candidates) {
    const value = getByPath(payload, key);
    if (typeof value === 'string' && value.startsWith('http')) {
      return value;
    }
  }

  const deepCandidate = findStringWithUrl(payload);
  return deepCandidate || '';
}

function findStringWithUrl(value) {
  if (!value) {
    return '';
  }

  if (typeof value === 'string' && value.startsWith('http')) {
    return value;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = findStringWithUrl(item);
      if (nested) {
        return nested;
      }
    }
    return '';
  }

  if (typeof value === 'object') {
    for (const key of Object.keys(value)) {
      const nested = findStringWithUrl(value[key]);
      if (nested) {
        return nested;
      }
    }
  }

  return '';
}

async function callInfinitePay(path, body) {
  try {
    const url = `${INFINITEPAY_API_BASE}${path}`;
    const response = await axios.post(url, body, {
      timeout: 15000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    return response.data;
  } catch (error) {
    const status = error.response?.status || 502;
    const details = error.response?.data || null;
    console.error('[infinitepay] erro:', status, details || error.message);

    const wrapped = new Error('Falha na comunicacao com InfinitePay.');
    wrapped.statusCode = status;
    wrapped.publicMessage = 'Erro ao comunicar com o checkout da InfinitePay.';
    throw wrapped;
  }
}

function ensureOrderAccess(user, order) {
  if (!order) {
    const error = new Error('Pedido nao encontrado.');
    error.statusCode = 404;
    error.publicMessage = 'Pedido nao encontrado.';
    throw error;
  }

  if (!user) {
    const error = new Error('Autenticacao obrigatoria.');
    error.statusCode = 401;
    error.publicMessage = 'Login obrigatorio para consultar este pedido.';
    throw error;
  }

  const email = String(user.email || '').toLowerCase();
  const isAdmin = ADMIN_EMAILS.includes(email);

  if (isAdmin) {
    return;
  }

  if (!order.userId || order.userId !== user.uid) {
    const error = new Error('Sem permissao para acessar este pedido.');
    error.statusCode = 403;
    error.publicMessage = 'Voce nao tem permissao para acessar este pedido.';
    throw error;
  }
}

async function ensureIntegrityOrBlock(orderRef, order) {
  const expected = signIntegrity(order);
  const current = String(order.integrity?.digest || '');
  const amountMatches = Number(order.amountCents || 0) === Number(order.payment?.amountCents || order.amountCents || 0);
  const chatPaymentConsistency = !order.chat?.unlocked || Boolean(order.payment?.paid);

  if (expected === current && amountMatches && chatPaymentConsistency) {
    return true;
  }

  await orderRef.set({
    'integrity.status': 'tampered',
    'integrity.lastVerifiedISO': new Date().toISOString(),
    'chat.unlocked': false,
    'payment.status': 'blocked',
    updatedAtISO: new Date().toISOString(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  const error = new Error('Integridade do pedido comprometida.');
  error.statusCode = 409;
  error.publicMessage = 'Detectamos adulteracao no pedido. Contate o suporte.';
  throw error;
}

function signIntegrity(order) {
  const critical = {
    orderId: normalizeOrderId(order.orderId),
    userId: order.userId || '',
    planLevel: order.planLevel || '',
    projectType: order.projectType || '',
    amountCents: Number(order.amountCents || order.payment?.amountCents || 0),
    createdAtISO: order.createdAtISO || ''
  };

  return crypto
    .createHmac('sha256', ORDER_HMAC_SECRET)
    .update(JSON.stringify(critical))
    .digest('hex');
}

function calculateBudget(type, pages, extrasCount, deadline, level) {
  const fixedBudgets = {
    Basic: { min: 900, max: 1200 },
    Medium: { min: 1800, max: 2500 },
    Profissional: { min: 3500, max: 5000 }
  };

  return fixedBudgets[level] || fixedBudgets.Basic;
}

function inferProjectType(planLevel, extras) {
  const selectedExtras = Array.isArray(extras) ? extras : [];
  const priorityByExtra = [
    { extra: 'Loja virtual', type: 'Loja Virtual' },
    { extra: 'Painel admin', type: 'Painel Admin' },
    { extra: 'Login', type: 'Login' },
    { extra: 'Integração com WhatsApp', type: 'Integração com WhatsApp' },
    { extra: 'SEO', type: 'SEO' },
    { extra: 'Responsividade premium', type: 'Responsividade Premium' },
    { extra: 'Landing page', type: 'Landing Page' }
  ];

  const matched = priorityByExtra.find(item => selectedExtras.includes(item.extra));
  if (matched) {
    return matched.type;
  }

  if (planLevel === 'Medium') {
    return 'Loja Virtual';
  }

  if (planLevel === 'Profissional') {
    return 'Painel Admin';
  }

  return 'Landing Page';
}

function sanitizeProjectType(value) {
  const text = sanitizeString(value, 90);
  if (text.toLowerCase() === 'integracao com whatsapp') {
    return 'Integracao com WhatsApp';
  }
  return text;
}

function formatBudget(min, max) {
  const minText = Number(min || 0).toLocaleString('pt-BR');
  const maxText = Number(max || 0).toLocaleString('pt-BR');
  return `Faixa estimada: R$ ${minText} - R$ ${maxText}`;
}

function sanitizeString(value, maxLen) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  return text.slice(0, maxLen);
}

function sanitizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return '';
  }
  return email.slice(0, 180);
}

function normalizeOrderId(value) {
  const raw = String(value || '').trim().toUpperCase();
  if (!raw) {
    return '';
  }
  return raw.replace(/[^A-Z0-9-]/g, '').slice(0, 32);
}

function generateOrderId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i += 1) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `ZELPYRN-${code}`;
}

function getByPath(obj, path) {
  if (!obj || !path) {
    return undefined;
  }
  return path.split('.').reduce((acc, key) => {
    if (!acc || typeof acc !== 'object') {
      return undefined;
    }
    return acc[key];
  }, obj);
}

function extractFirstString(obj, keys) {
  for (const key of keys) {
    const value = getByPath(obj, key);
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}
