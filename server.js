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
const EMAILJS_SERVICE_ID = (process.env.EMAILJS_SERVICE_ID || 'service_37zjx24').trim();
const EMAILJS_TEMPLATE_ID = (process.env.EMAILJS_TEMPLATE_ID || 'template_vxh3c9g').trim();
const EMAILJS_PUBLIC_KEY = (process.env.EMAILJS_PUBLIC_KEY || 'x5hcmELDSLfjTS8I0').trim();
const EMAILJS_PRIVATE_KEY = (process.env.EMAILJS_PRIVATE_KEY || '').trim();
const PASSWORD_RESET_CODE_TTL_MS = 10 * 60 * 1000;
const PASSWORD_RESET_RESEND_COOLDOWN_MS = 60 * 1000;
const PASSWORD_RESET_SESSION_TTL_MS = 15 * 60 * 1000;
const PASSWORD_RESET_MAX_FAILED_ATTEMPTS = 5;
const PASSWORD_RESET_MAX_SENDS_PER_HOUR = 5;

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

// Admin Claims System
app.post('/api/orders/claim', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { orderId } = req.body || {};
    const normalizedOrderId = normalizeOrderId(orderId);

    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'orderId obrigatorio.' });
    }

    const email = normalizeEmail(user.email);
    if (!isAdminEmail(email)) {
      return res.status(403).json({ success: false, error: 'Apenas administradores podem reivindicar pedidos.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const nowISO = new Date().toISOString();
    const adminName = user.displayName || extractNameFromEmail(email);
    const claimedBy = await db.runTransaction(async transaction => {
      const orderDoc = await transaction.get(orderRef);

      if (!orderDoc.exists) {
        throw createHttpError(404, 'Pedido nao encontrado.');
      }

      const order = orderDoc.data() || {};
      const currentClaim = buildClaimedBySummary(order);
      const alreadyClaimedByCurrentAdmin = currentClaim.adminId === user.uid || currentClaim.email === email;

      if (order.completedByAdminId || order.completedByAdminEmail) {
        throw createHttpError(409, 'Este pedido ja foi concluido e nao pode ser reivindicado novamente.', {
          completedBy: buildCompletedBySummary(order)
        });
      }

      if ((currentClaim.adminId || currentClaim.email) && !alreadyClaimedByCurrentAdmin) {
        throw createHttpError(409, 'Este pedido ja foi reivindicado por outro admin.', {
          claimedBy: currentClaim
        });
      }

      if (!alreadyClaimedByCurrentAdmin) {
        transaction.set(orderRef, {
          claimedByAdminId: user.uid,
          claimedByAdminEmail: email,
          claimedByAdminName: adminName,
          claimedAt: admin.firestore.FieldValue.serverTimestamp(),
          claimedAtISO: nowISO,
          updatedAtISO: nowISO,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }

      return {
        adminId: user.uid,
        name: adminName,
        email
      };
    });

    res.json({
      success: true,
      orderId: normalizedOrderId,
      claimedBy
    });
  } catch (error) {
    console.error('[claim-order] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao reivindicar pedido.',
      claimedBy: error.claimedBy || null,
      completedBy: error.completedBy || null
    });
  }
});

app.post('/api/orders/release-admin', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { orderId, releaseeEmail } = req.body || {};
    const normalizedOrderId = normalizeOrderId(orderId);
    const email = normalizeEmail(user.email);

    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'orderId obrigatorio.' });
    }

    if (!releaseeEmail || !String(releaseeEmail).includes('@')) {
      return res.status(400).json({ success: false, error: 'Email do admin invalido.' });
    }

    const releaseeEmailNormalized = String(releaseeEmail).trim().toLowerCase();

    if (!isAdminEmail(email)) {
      return res.status(403).json({ success: false, error: 'Apenas administradores podem liberar acesso.' });
    }

    if (!isAdminEmail(releaseeEmailNormalized)) {
      return res.status(400).json({ success: false, error: 'Email do admin nao esta registrado.' });
    }

    const releaseeIdentity = await resolveAdminIdentityByEmail(releaseeEmailNormalized);
    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const nowISO = new Date().toISOString();
    const released = await db.runTransaction(async transaction => {
      const orderDoc = await transaction.get(orderRef);

      if (!orderDoc.exists) {
        throw createHttpError(404, 'Pedido nao encontrado.');
      }

      const order = orderDoc.data() || {};
      ensurePrincipalAdminOrThrow(order, user.uid, email, 'Apenas o admin principal pode liberar outros admins.');

      if (!order.claimedByAdminId && !order.claimedByAdminEmail) {
        throw createHttpError(409, 'O pedido precisa ser reivindicado antes de liberar outro admin.');
      }

      if (order.completedByAdminId || order.completedByAdminEmail) {
        throw createHttpError(409, 'Pedido ja concluido. Nao e possivel liberar novos admins.');
      }

      if (releaseeEmailNormalized === email) {
        throw createHttpError(400, 'Voce ja eh o admin principal, nao pode se liberar.');
      }

      const releasedAdmins = normalizeReleasedAdminsForServer(order.releasedAdmins);
      const alreadyReleased = releasedAdmins.some(item => item.email === releaseeEmailNormalized);

      if (alreadyReleased) {
        throw createHttpError(409, 'Este admin ja foi liberado para este pedido.');
      }

      releasedAdmins.push({
        uid: releaseeIdentity.uid,
        name: releaseeIdentity.name,
        email: releaseeIdentity.email,
        releasedAt: admin.firestore.Timestamp.now(),
        releasedAtISO: nowISO,
        releasedByAdminId: user.uid
      });

      transaction.set(orderRef, {
        releasedAdmins,
        updatedAtISO: nowISO,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return {
        uid: releaseeIdentity.uid,
        name: releaseeIdentity.name,
        email: releaseeIdentity.email
      };
    });

    res.json({
      success: true,
      orderId: normalizedOrderId,
      released
    });
  } catch (error) {
    console.error('[release-admin] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao liberar admin.'
    });
  }
});

app.post('/api/orders/remove-released-admin', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { orderId, adminEmail } = req.body || {};
    const normalizedOrderId = normalizeOrderId(orderId);
    const email = normalizeEmail(user.email);

    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'orderId obrigatorio.' });
    }

    if (!adminEmail || !String(adminEmail).includes('@')) {
      return res.status(400).json({ success: false, error: 'Email do admin invalido.' });
    }

    const adminEmailNormalized = String(adminEmail).trim().toLowerCase();

    if (!isAdminEmail(email)) {
      return res.status(403).json({ success: false, error: 'Apenas administradores podem remover acesso.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const nowISO = new Date().toISOString();
    await db.runTransaction(async transaction => {
      const orderDoc = await transaction.get(orderRef);

      if (!orderDoc.exists) {
        throw createHttpError(404, 'Pedido nao encontrado.');
      }

      const order = orderDoc.data() || {};
      ensurePrincipalAdminOrThrow(order, user.uid, email, 'Apenas o admin principal pode remover acesso de outros admins.');

      const releasedAdmins = normalizeReleasedAdminsForServer(order.releasedAdmins);
      const filtered = releasedAdmins.filter(item => item.email !== adminEmailNormalized);

      if (filtered.length === releasedAdmins.length) {
        throw createHttpError(404, 'Admin nao encontrado na lista de liberados.');
      }

      transaction.set(orderRef, {
        releasedAdmins: filtered,
        updatedAtISO: nowISO,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    });

    res.json({
      success: true,
      orderId: normalizedOrderId,
      removed: {
        email: adminEmailNormalized
      }
    });
  } catch (error) {
    console.error('[remove-released-admin] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao remover admin.'
    });
  }
});

app.post('/api/orders/complete', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { orderId } = req.body || {};
    const normalizedOrderId = normalizeOrderId(orderId);

    if (!normalizedOrderId) {
      return res.status(400).json({ success: false, error: 'orderId obrigatorio.' });
    }

    const email = normalizeEmail(user.email);
    if (!isAdminEmail(email)) {
      return res.status(403).json({ success: false, error: 'Apenas administradores podem concluir pedidos.' });
    }

    const orderRef = db.collection('orders').doc(normalizedOrderId);
    const nowISO = new Date().toISOString();
    const adminName = user.displayName || extractNameFromEmail(email);
    const completedBy = await db.runTransaction(async transaction => {
      const orderDoc = await transaction.get(orderRef);

      if (!orderDoc.exists) {
        throw createHttpError(404, 'Pedido nao encontrado.');
      }

      const order = orderDoc.data() || {};
      ensurePrincipalAdminOrThrow(order, user.uid, email, 'Apenas o admin principal pode concluir o pedido.');

      const currentCompletion = buildCompletedBySummary(order);
      const alreadyCompletedByCurrentAdmin = currentCompletion.adminId === user.uid || currentCompletion.email === email;

      if ((currentCompletion.adminId || currentCompletion.email) && !alreadyCompletedByCurrentAdmin) {
        throw createHttpError(409, 'Este pedido ja foi concluido por outro admin.', {
          completedBy: currentCompletion
        });
      }

      if (!alreadyCompletedByCurrentAdmin) {
        transaction.set(orderRef, {
          completedByAdminId: user.uid,
          completedByAdminEmail: email,
          completedByAdminName: adminName,
          completedAt: admin.firestore.FieldValue.serverTimestamp(),
          completedAtISO: nowISO,
          status: 'Pedido finalizado',
          updatedAtISO: nowISO,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }

      return {
        adminId: user.uid,
        name: adminName,
        email
      };
    });

    res.json({
      success: true,
      orderId: normalizedOrderId,
      completedBy,
      newStatus: 'Pedido finalizado'
    });
  } catch (error) {
    console.error('[complete-order] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao concluir pedido.',
      completedBy: error.completedBy || null
    });
  }
});

app.get('/api/admin/stats', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const email = normalizeEmail(user.email);

    if (!isAdminEmail(email)) {
      return res.status(403).json({ success: false, error: 'Apenas administradores podem acessar estatisticas.' });
    }
    const adminSnapshot = await computeAdminStatsSnapshot(user.uid, email, user.displayName);
    const ownStats = adminSnapshot.stats;

    res.json({
      success: true,
      stats: {
        totalCompleted: ownStats.totalCompleted,
        completedThisMonth: ownStats.completedThisMonth,
        currentlyClaimed: ownStats.currentlyClaimed,
        totalClaimed: ownStats.totalClaimed,
        rankingPosition: ownStats.position,
        adminEmail: email,
        adminId: user.uid,
        adminName: ownStats.adminName
      },
      ranking: adminSnapshot.ranking
    });
  } catch (error) {
    console.error('[admin-stats] erro:', error);
    const statusCode = error.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao carregar estatisticas.'
    });
  }
});

app.get('/api/profile/me', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const email = normalizeEmail(user.email);
    const role = isAdminEmail(email) ? 'admin' : 'client';
    const authRecord = await getAuthRecordSafe(user.uid);
    const profile = await syncUserProfileRecord(user, authRecord);

    if (role === 'admin') {
      const adminSnapshot = await computeAdminStatsSnapshot(user.uid, email, profile.name);
      return res.json({
        success: true,
        profile,
        stats: {
          type: 'admin',
          totalClaimed: adminSnapshot.stats.totalClaimed,
          currentlyClaimed: adminSnapshot.stats.currentlyClaimed,
          totalCompleted: adminSnapshot.stats.totalCompleted,
          completedThisMonth: adminSnapshot.stats.completedThisMonth,
          rankingPosition: adminSnapshot.stats.rankingPosition
        },
        ranking: adminSnapshot.ranking.slice(0, 10)
      });
    }

    const clientStats = await computeClientStats(user.uid);
    return res.json({
      success: true,
      profile,
      stats: {
        type: 'client',
        totalOrdersCreated: clientStats.totalOrdersCreated,
        totalPaidOrders: clientStats.totalPaidOrders,
        totalCompletedOrders: clientStats.totalCompletedOrders
      }
    });
  } catch (error) {
    console.error('[profile-me] erro:', error);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao carregar perfil.'
    });
  }
});

app.post('/api/profile/update', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const email = normalizeEmail(user.email);
    const authRecord = await getAuthRecordSafe(user.uid);
    const body = req.body || {};
    const nextName = Object.prototype.hasOwnProperty.call(body, 'name') ? sanitizeString(body.name, 120) : null;
    const nextPhotoURL = Object.prototype.hasOwnProperty.call(body, 'photoURL') ? sanitizeProfilePhotoURL(body.photoURL) : null;
    const authUpdates = {};
    const profileUpdates = {};

    if (nextName !== null) {
      if (!nextName || nextName.length < 2) {
        return res.status(400).json({ success: false, error: 'Nome invalido. Use pelo menos 2 caracteres.' });
      }
      authUpdates.displayName = nextName;
      profileUpdates.name = nextName;
    }

    if (nextPhotoURL !== null) {
      authUpdates.photoURL = nextPhotoURL || null;
      profileUpdates.photoURL = nextPhotoURL;
    }

    if (!Object.keys(authUpdates).length) {
      return res.status(400).json({ success: false, error: 'Nenhum dado valido foi enviado para atualizar o perfil.' });
    }

    await admin.auth().updateUser(user.uid, authUpdates);
    const profile = await syncUserProfileRecord(user, authRecord, {
      ...profileUpdates,
      email,
      updatedAtISO: new Date().toISOString()
    });

    return res.json({
      success: true,
      profile
    });
  } catch (error) {
    console.error('[profile-update] erro:', error);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao atualizar perfil.'
    });
  }
});

app.post('/api/profile/password/send-code', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const email = normalizeEmail(user.email);
    if (!email) {
      return res.status(400).json({ success: false, error: 'Sua conta precisa ter email valido para redefinir a senha.' });
    }

    const flowRef = db.collection('passwordResetFlows').doc(user.uid);
    const code = generatePasswordResetCode();
    const now = new Date();
    const nowISO = now.toISOString();
    const expiresAtISO = new Date(now.getTime() + PASSWORD_RESET_CODE_TTL_MS).toISOString();
    const resendAvailableAtISO = new Date(now.getTime() + PASSWORD_RESET_RESEND_COOLDOWN_MS).toISOString();
    const codeHash = hashPasswordResetCode(user.uid, code);

    const transactionResult = await db.runTransaction(async transaction => {
      const flowDoc = await transaction.get(flowRef);
      const flow = flowDoc.exists ? (flowDoc.data() || {}) : {};
      const resendAvailableAt = parseISOToMillis(flow.resendAvailableAtISO);
      const sendWindowStartedAt = parseISOToMillis(flow.sendWindowStartedAtISO);
      const withinWindow = sendWindowStartedAt && (now.getTime() - sendWindowStartedAt) < (60 * 60 * 1000);
      const sendCountInWindow = withinWindow ? Number(flow.sendCountInWindow || 0) : 0;

      if (resendAvailableAt && resendAvailableAt > now.getTime()) {
        return {
          ok: false,
          statusCode: 429,
          publicMessage: 'Aguarde um pouco antes de pedir outro codigo.'
        };
      }

      if (sendCountInWindow >= PASSWORD_RESET_MAX_SENDS_PER_HOUR) {
        return {
          ok: false,
          statusCode: 429,
          publicMessage: 'Voce atingiu o limite de codigos enviados nesta hora.'
        };
      }

      transaction.set(flowRef, {
        uid: user.uid,
        email,
        status: 'code_sent',
        codeHash,
        expiresAtISO,
        resendAvailableAtISO,
        sendWindowStartedAtISO: withinWindow ? flow.sendWindowStartedAtISO : nowISO,
        sendCountInWindow: sendCountInWindow + 1,
        failedAttempts: 0,
        sessionTokenHash: '',
        sessionExpiresAtISO: '',
        verifiedAtISO: '',
        updatedAtISO: nowISO,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return { ok: true };
    });

    if (!transactionResult.ok) {
      return res.status(transactionResult.statusCode).json({
        success: false,
        error: transactionResult.publicMessage
      });
    }

    try {
      await sendEmailViaEmailJS({
        toEmail: email,
        subjectLine: 'Codigo de seguranca da sua conta',
        message: `Seu codigo para alterar a senha e: ${code}\n\nEsse codigo expira em 10 minutos.\nSe voce nao pediu essa alteracao, ignore este email.`
      });
    } catch (error) {
      await flowRef.set({
        status: 'send_failed',
        resendAvailableAtISO: nowISO,
        updatedAtISO: nowISO,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      console.error('[profile-password-send-code] falha ao enviar email:', {
        statusCode: error.statusCode || error.responseStatus || 502,
        publicMessage: error.publicMessage || error.message,
        provider: error.provider || 'emailjs',
        providerCode: error.providerCode || '',
        providerDetail: error.providerDetail || ''
      });

      return res.status(502).json({
        success: false,
        error: error.publicMessage || 'Nao foi possivel enviar o codigo por email agora. Tente novamente.'
      });
    }

    return res.json({
      success: true,
      expiresAtISO,
      resendAvailableAtISO
    });
  } catch (error) {
    console.error('[profile-password-send-code] erro:', error);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao enviar codigo de seguranca.'
    });
  }
});

app.post('/api/profile/password/verify-code', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const inputCode = String(req.body?.code || '').trim();

    if (!/^\d{6}$/.test(inputCode)) {
      return res.status(400).json({ success: false, error: 'Digite um codigo valido com 6 numeros.' });
    }

    const flowRef = db.collection('passwordResetFlows').doc(user.uid);
    const now = new Date();
    const nowISO = now.toISOString();
    const sessionToken = generatePasswordResetSessionToken();
    const sessionTokenHash = hashPasswordResetSessionToken(user.uid, sessionToken);
    const sessionExpiresAtISO = new Date(now.getTime() + PASSWORD_RESET_SESSION_TTL_MS).toISOString();

    const verification = await db.runTransaction(async transaction => {
      const flowDoc = await transaction.get(flowRef);
      if (!flowDoc.exists) {
        return {
          ok: false,
          statusCode: 404,
          publicMessage: 'Nenhum codigo foi enviado ainda para sua conta.'
        };
      }

      const flow = flowDoc.data() || {};
      const failedAttempts = Number(flow.failedAttempts || 0);
      const expiresAt = parseISOToMillis(flow.expiresAtISO);

      if (!flow.codeHash || flow.status === 'completed') {
        return {
          ok: false,
          statusCode: 400,
          publicMessage: 'Esse codigo nao esta mais disponivel. Peça um novo envio.'
        };
      }

      if (expiresAt && expiresAt < now.getTime()) {
        transaction.set(flowRef, {
          status: 'expired',
          updatedAtISO: nowISO,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        return {
          ok: false,
          statusCode: 400,
          publicMessage: 'Esse codigo expirou. Peça um novo envio.'
        };
      }

      if (failedAttempts >= PASSWORD_RESET_MAX_FAILED_ATTEMPTS) {
        return {
          ok: false,
          statusCode: 429,
          publicMessage: 'Muitas tentativas incorretas. Peça um novo codigo.'
        };
      }

      const expectedHash = hashPasswordResetCode(user.uid, inputCode);
      if (expectedHash !== flow.codeHash) {
        const nextAttempts = failedAttempts + 1;
        transaction.set(flowRef, {
          failedAttempts: nextAttempts,
          status: nextAttempts >= PASSWORD_RESET_MAX_FAILED_ATTEMPTS ? 'blocked' : 'code_sent',
          updatedAtISO: nowISO,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return {
          ok: false,
          statusCode: nextAttempts >= PASSWORD_RESET_MAX_FAILED_ATTEMPTS ? 429 : 400,
          publicMessage: nextAttempts >= PASSWORD_RESET_MAX_FAILED_ATTEMPTS
            ? 'Codigo bloqueado por excesso de tentativas. Peça um novo envio.'
            : 'Codigo incorreto.'
        };
      }

      transaction.set(flowRef, {
        status: 'verified',
        verifiedAtISO: nowISO,
        sessionTokenHash,
        sessionExpiresAtISO,
        failedAttempts,
        updatedAtISO: nowISO,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return {
        ok: true
      };
    });

    if (!verification.ok) {
      return res.status(verification.statusCode).json({
        success: false,
        error: verification.publicMessage
      });
    }

    return res.json({
      success: true,
      sessionToken,
      sessionExpiresAtISO
    });
  } catch (error) {
    console.error('[profile-password-verify-code] erro:', error);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao verificar codigo.'
    });
  }
});

app.post('/api/profile/password/update', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const sessionToken = String(req.body?.sessionToken || '').trim();
    const newPassword = String(req.body?.newPassword || '');

    if (!sessionToken) {
      return res.status(400).json({ success: false, error: 'Sessao de verificacao invalida.' });
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        error: 'Use uma senha com pelo menos 8 caracteres, incluindo letra e numero.'
      });
    }

    const flowRef = db.collection('passwordResetFlows').doc(user.uid);
    const now = new Date();
    const nowISO = now.toISOString();
    const sessionTokenHash = hashPasswordResetSessionToken(user.uid, sessionToken);

    const validation = await db.runTransaction(async transaction => {
      const flowDoc = await transaction.get(flowRef);
      if (!flowDoc.exists) {
        return {
          ok: false,
          statusCode: 404,
          publicMessage: 'Nao encontramos uma verificacao valida para esta conta.'
        };
      }

      const flow = flowDoc.data() || {};
      const sessionExpiresAt = parseISOToMillis(flow.sessionExpiresAtISO);

      if (flow.status !== 'verified' || !flow.sessionTokenHash) {
        return {
          ok: false,
          statusCode: 400,
          publicMessage: 'Seu codigo ainda nao foi validado.'
        };
      }

      if (flow.sessionTokenHash !== sessionTokenHash) {
        return {
          ok: false,
          statusCode: 403,
          publicMessage: 'Sessao de verificacao invalida.'
        };
      }

      if (sessionExpiresAt && sessionExpiresAt < now.getTime()) {
        transaction.set(flowRef, {
          status: 'expired',
          updatedAtISO: nowISO,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        return {
          ok: false,
          statusCode: 400,
          publicMessage: 'Sua verificacao expirou. Envie um novo codigo.'
        };
      }

      return { ok: true };
    });

    if (!validation.ok) {
      return res.status(validation.statusCode).json({
        success: false,
        error: validation.publicMessage
      });
    }

    await admin.auth().updateUser(user.uid, { password: newPassword });
    await flowRef.set({
      status: 'completed',
      codeHash: '',
      sessionTokenHash: '',
      sessionExpiresAtISO: '',
      completedAtISO: nowISO,
      updatedAtISO: nowISO,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return res.json({
      success: true
    });
  } catch (error) {
    console.error('[profile-password-update] erro:', error);
    const statusCode = error.statusCode || 500;
    return res.status(statusCode).json({
      success: false,
      error: error.publicMessage || 'Falha ao atualizar senha.'
    });
  }
});

function extractNameFromEmail(email) {
  const normalized = String(email || '').trim().toLowerCase();
  if (!normalized) {
    return 'Admin';
  }
  const localPart = normalized.split('@')[0] || 'admin';
  return localPart.replace(/[._-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isAdminEmail(email) {
  return ADMIN_EMAILS.includes(normalizeEmail(email));
}

function createHttpError(statusCode, publicMessage, extra = {}) {
  const error = new Error(publicMessage);
  error.statusCode = statusCode;
  error.publicMessage = publicMessage;
  Object.assign(error, extra);
  return error;
}

function buildClaimedBySummary(order) {
  return {
    adminId: String(order?.claimedByAdminId || ''),
    name: String(order?.claimedByAdminName || extractNameFromEmail(order?.claimedByAdminEmail || 'admin@local')),
    email: normalizeEmail(order?.claimedByAdminEmail)
  };
}

function buildCompletedBySummary(order) {
  return {
    adminId: String(order?.completedByAdminId || ''),
    name: String(order?.completedByAdminName || extractNameFromEmail(order?.completedByAdminEmail || 'admin@local')),
    email: normalizeEmail(order?.completedByAdminEmail)
  };
}

function ensurePrincipalAdminOrThrow(order, userId, email, publicMessage) {
  const claimedByUserId = String(order?.claimedByAdminId || '');
  const claimedByEmail = normalizeEmail(order?.claimedByAdminEmail);
  const currentEmail = normalizeEmail(email);

  if (!claimedByUserId && !claimedByEmail) {
    throw createHttpError(409, 'Este pedido ainda nao possui admin principal.');
  }

  if (claimedByUserId === userId || claimedByEmail === currentEmail) {
    return;
  }

  throw createHttpError(403, publicMessage);
}

function normalizeReleasedAdminsForServer(list) {
  if (!Array.isArray(list)) {
    return [];
  }

  return list
    .map(item => ({
      uid: String(item?.uid || ''),
      name: String(item?.name || extractNameFromEmail(item?.email || 'admin@local')),
      email: normalizeEmail(item?.email),
      releasedAt: item?.releasedAt || null,
      releasedAtISO: String(item?.releasedAtISO || ''),
      releasedByAdminId: String(item?.releasedByAdminId || '')
    }))
    .filter(item => Boolean(item.email));
}

async function resolveAdminIdentityByEmail(email) {
  const normalized = normalizeEmail(email);
  const fallback = {
    uid: '',
    email: normalized,
    name: extractNameFromEmail(normalized)
  };

  try {
    const authUser = await admin.auth().getUserByEmail(normalized);
    return {
      uid: authUser.uid || '',
      email: normalizeEmail(authUser.email) || normalized,
      name: authUser.displayName || extractNameFromEmail(authUser.email || normalized)
    };
  } catch (error) {
    return fallback;
  }
}

function ensureRankingEntry(rankingMap, identity) {
  const adminEmail = normalizeEmail(identity?.adminEmail);
  const adminId = String(identity?.adminId || '').trim();
  const mapKey = adminEmail || adminId || `admin-${rankingMap.size + 1}`;
  const existing = rankingMap.get(mapKey);

  if (existing) {
    if (!existing.adminId && adminId) {
      existing.adminId = adminId;
    }
    if (!existing.adminEmail && adminEmail) {
      existing.adminEmail = adminEmail;
    }
    if ((!existing.adminName || existing.adminName === 'Admin') && identity?.adminName) {
      existing.adminName = String(identity.adminName);
    }
    return existing;
  }

  const entry = {
    adminId,
    adminEmail,
    adminName: String(identity?.adminName || extractNameFromEmail(adminEmail || 'admin@local')),
    totalClaimed: 0,
    claimedOpen: 0,
    totalCompleted: 0,
    completedThisMonth: 0
  };

  rankingMap.set(mapKey, entry);
  return entry;
}

async function computeAdminStatsSnapshot(userId, email, displayName) {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const monthStartISO = monthStart.toISOString();
  const ordersSnapshot = await db.collection('orders').get();
  const rankingMap = new Map();

  ADMIN_EMAILS.forEach(adminEmail => {
    const normalizedAdminEmail = normalizeEmail(adminEmail);
    rankingMap.set(normalizedAdminEmail, {
      adminId: '',
      adminEmail: normalizedAdminEmail,
      adminName: extractNameFromEmail(normalizedAdminEmail),
      totalClaimed: 0,
      claimedOpen: 0,
      totalCompleted: 0,
      completedThisMonth: 0
    });
  });

  ordersSnapshot.forEach(doc => {
    const order = doc.data() || {};
    const claimedEmail = normalizeEmail(order.claimedByAdminEmail);
    const claimedId = String(order.claimedByAdminId || '').trim();
    const completedEmail = normalizeEmail(order.completedByAdminEmail);
    const completedId = String(order.completedByAdminId || '').trim();
    const isCompleted = Boolean(completedEmail || completedId);

    if (claimedEmail || claimedId) {
      const claimedEntry = ensureRankingEntry(rankingMap, {
        adminId: claimedId,
        adminEmail: claimedEmail,
        adminName: order.claimedByAdminName
      });
      claimedEntry.totalClaimed += 1;
      if (!isCompleted) {
        claimedEntry.claimedOpen += 1;
      }
    }

    if (completedEmail || completedId) {
      const completedEntry = ensureRankingEntry(rankingMap, {
        adminId: completedId,
        adminEmail: completedEmail,
        adminName: order.completedByAdminName
      });
      completedEntry.totalCompleted += 1;
      if (order.completedAtISO && order.completedAtISO >= monthStartISO) {
        completedEntry.completedThisMonth += 1;
      }
    }
  });

  const ranking = Array.from(rankingMap.values())
    .sort((left, right) => (
      right.totalCompleted - left.totalCompleted
      || right.completedThisMonth - left.completedThisMonth
      || right.claimedOpen - left.claimedOpen
      || left.adminName.localeCompare(right.adminName, 'pt-BR')
    ))
    .map((entry, index) => ({
      position: index + 1,
      adminId: entry.adminId,
      adminEmail: entry.adminEmail,
      adminName: entry.adminName,
      totalClaimed: entry.totalClaimed,
      currentlyClaimed: entry.claimedOpen,
      totalCompleted: entry.totalCompleted,
      completedThisMonth: entry.completedThisMonth
    }));

  const ownStats = ranking.find(item => item.adminId === userId || item.adminEmail === email) || {
    position: ranking.length + 1,
    adminId: userId,
    adminEmail: email,
    adminName: displayName || extractNameFromEmail(email),
    totalClaimed: 0,
    currentlyClaimed: 0,
    totalCompleted: 0,
    completedThisMonth: 0
  };

  return {
    stats: {
      totalCompleted: ownStats.totalCompleted,
      completedThisMonth: ownStats.completedThisMonth,
      currentlyClaimed: ownStats.currentlyClaimed,
      totalClaimed: ownStats.totalClaimed,
      rankingPosition: ownStats.position,
      adminName: ownStats.adminName
    },
    ranking
  };
}

async function computeClientStats(userId) {
  const ordersSnapshot = await db.collection('orders')
    .where('userId', '==', userId)
    .get();

  let totalPaidOrders = 0;
  let totalCompletedOrders = 0;

  ordersSnapshot.forEach(doc => {
    const order = doc.data() || {};
    if (Boolean(order.payment?.paid)) {
      totalPaidOrders += 1;
    }
    if (String(order.status || '').toLowerCase() === 'pedido finalizado') {
      totalCompletedOrders += 1;
    }
  });

  return {
    totalOrdersCreated: ordersSnapshot.size,
    totalPaidOrders,
    totalCompletedOrders
  };
}

async function getAuthRecordSafe(uid) {
  try {
    return await admin.auth().getUser(uid);
  } catch (error) {
    return null;
  }
}

async function syncUserProfileRecord(user, authRecord, extraUpdates = {}) {
  const email = normalizeEmail(extraUpdates.email || user.email || authRecord?.email);
  const role = isAdminEmail(email) ? 'admin' : 'client';
  const profileRef = db.collection('userProfiles').doc(user.uid);
  const profileDoc = await profileRef.get();
  const currentProfile = profileDoc.exists ? (profileDoc.data() || {}) : {};
  const createdAtISO = currentProfile.createdAtISO
    || toISOStringSafe(authRecord?.metadata?.creationTime)
    || currentProfile.updatedAtISO
    || new Date().toISOString();
  const requestedUpdatedAtISO = extraUpdates.updatedAtISO || new Date().toISOString();
  const profile = {
    uid: user.uid,
    name: sanitizeString(
      extraUpdates.name
      || currentProfile.name
      || user.displayName
      || authRecord?.displayName
      || extractNameFromEmail(email),
      120
    ) || extractNameFromEmail(email || 'cliente@local'),
    email,
    role,
    photoURL: sanitizeProfilePhotoURL(
      Object.prototype.hasOwnProperty.call(extraUpdates, 'photoURL')
        ? extraUpdates.photoURL
        : (currentProfile.photoURL || user.photoURL || authRecord?.photoURL || '')
    ) || '',
    createdAtISO,
    updatedAtISO: currentProfile.updatedAtISO || createdAtISO
  };

  const shouldWrite = !profileDoc.exists
    || profile.name !== String(currentProfile.name || '')
    || profile.email !== normalizeEmail(currentProfile.email)
    || profile.role !== String(currentProfile.role || '')
    || profile.photoURL !== String(currentProfile.photoURL || '')
    || Boolean(extraUpdates.updatedAtISO)
    || Object.prototype.hasOwnProperty.call(extraUpdates, 'name')
    || Object.prototype.hasOwnProperty.call(extraUpdates, 'photoURL');

  if (shouldWrite) {
    profile.updatedAtISO = requestedUpdatedAtISO;
    await profileRef.set({
      ...profile,
      createdAt: currentProfile.createdAt || admin.firestore.Timestamp.fromDate(new Date(createdAtISO)),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  }

  return profile;
}

function sanitizeProfilePhotoURL(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '';
  }
  if (!/^https?:\/\//i.test(normalized)) {
    const error = createHttpError(400, 'URL da foto de perfil invalida.');
    throw error;
  }
  return normalized.slice(0, 2000);
}

function toISOStringSafe(value) {
  if (!value) {
    return '';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString();
}

function parseISOToMillis(value) {
  if (!value) {
    return 0;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? 0 : parsed.getTime();
}

function generatePasswordResetCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function generatePasswordResetSessionToken() {
  return crypto.randomBytes(24).toString('hex');
}

function hashPasswordResetCode(uid, code) {
  return crypto
    .createHmac('sha256', ORDER_HMAC_SECRET)
    .update(`password-reset-code:${uid}:${String(code || '').trim()}`)
    .digest('hex');
}

function hashPasswordResetSessionToken(uid, token) {
  return crypto
    .createHmac('sha256', ORDER_HMAC_SECRET)
    .update(`password-reset-session:${uid}:${String(token || '').trim()}`)
    .digest('hex');
}

function isStrongPassword(password) {
  const value = String(password || '');
  return value.length >= 8 && /[A-Za-z]/.test(value) && /\d/.test(value);
}

async function sendEmailViaEmailJS({ toEmail, subjectLine, message }) {
  try {
    const payload = {
      service_id: EMAILJS_SERVICE_ID,
      template_id: EMAILJS_TEMPLATE_ID,
      user_id: EMAILJS_PUBLIC_KEY,
      template_params: {
        user_email: toEmail,
        reply_to: toEmail,
        order_id: 'Conta',
        plan: subjectLine,
        message
      }
    };

    if (EMAILJS_PRIVATE_KEY) {
      payload.accessToken = EMAILJS_PRIVATE_KEY;
    }

    await axios.post('https://api.emailjs.com/api/v1.0/email/send', payload, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
  } catch (error) {
    const responseStatus = error.response?.status || 502;
    const responseData = error.response?.data;
    const responseText = typeof responseData === 'string'
      ? responseData
      : JSON.stringify(responseData || {});
    const providerDetail = String(responseText || error.message || '').slice(0, 300);

    console.error('[emailjs] erro ao enviar email:', {
      status: responseStatus,
      serviceId: EMAILJS_SERVICE_ID,
      templateId: EMAILJS_TEMPLATE_ID,
      publicKeySuffix: EMAILJS_PUBLIC_KEY ? EMAILJS_PUBLIC_KEY.slice(-6) : '',
      privateKeyConfigured: Boolean(EMAILJS_PRIVATE_KEY),
      toEmail,
      detail: providerDetail
    });

    const wrapped = new Error(`EmailJS respondeu ${responseStatus}. ${providerDetail || 'Sem detalhe adicional.'}`);
    wrapped.statusCode = 502;
    wrapped.responseStatus = responseStatus;
    wrapped.provider = 'emailjs';
    wrapped.providerCode = `EMAILJS_${responseStatus}`;
    wrapped.providerDetail = providerDetail;
    wrapped.publicMessage = `Nao foi possivel enviar o codigo por email agora. EmailJS respondeu ${responseStatus}.`;
    throw wrapped;
  }
}

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
    claimedByAdminId: '',
    claimedByAdminName: '',
    claimedByAdminEmail: '',
    claimedAt: null,
    claimedAtISO: '',
    releasedAdmins: [],
    completedByAdminId: '',
    completedByAdminName: '',
    completedByAdminEmail: '',
    completedAt: null,
    completedAtISO: '',
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

  const email = normalizeEmail(user.email);
  const isAdmin = isAdminEmail(email);

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
