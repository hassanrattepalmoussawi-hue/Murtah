const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(express.json());

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;

// --- التحقق الأولي (يستدعيه Meta مرة وحدة عند تسجيل رابط الـ Webhook) ---
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

// --- استقبال الرسائل الفعلية من واتساب ---
app.post('/webhook', async (req, res) => {
  try {
    const messages = req.body.entry?.[0]?.changes?.[0]?.value?.messages;

    if (!messages || messages.length === 0) {
      return res.sendStatus(200);
    }

    for (const msg of messages) {
      await handleIncomingMessage(msg);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook error:', err);
    // دايماً رجّع 200 لواتساب حتى لو صار خطأ داخلي، وإلا يعيد المحاولة بشكل مزعج
    res.sendStatus(200);
  }
});

async function handleIncomingMessage(msg) {
  const fromNumber = msg.from;

  // نتجاهل أي نوع رسالة غير نصية (صور، صوت، ملصقات...)
  if (msg.type !== 'text' || !msg.text?.body) {
    console.log(`Ignored non-text message from: ${fromNumber}`);
    return;
  }

  const docRef = db.collection('phone_verifications').doc(fromNumber);
  const doc = await docRef.get();

  if (!doc.exists) {
    console.log(`No pending verification for: ${fromNumber}`);
    return;
  }

  const data = doc.data();

  if (data.status !== 'pending') {
    console.log(`Already resolved (${data.status}) for: ${fromNumber}`);
    return;
  }

  // فحص انتهاء الصلاحية
  const expiresAt = data.expiresAt?.toDate?.();
  if (expiresAt && new Date() > expiresAt) {
    await docRef.update({ status: 'expired' });
    console.log(`Expired verification for: ${fromNumber}`);
    return;
  }

  // التحقق الفعلي: استخراج الكود من نص الرسالة ومطابقته
  const extractedCode = extractCode(msg.text.body);
  const expectedCode = data.code;

  if (!extractedCode || extractedCode !== expectedCode) {
    console.log(
      `Code mismatch for ${fromNumber}: got "${extractedCode}", expected "${expectedCode}"`
    );
    return; // ما نوثق — الكود غلط أو مو موجود بالرسالة
  }

  // نبحث هل فيه حساب سابق مسجل بهذا الرقم (نفس صيغة الهاتف المخزنة بـ users)
  const usersSnap = await db.collection('users')
    .where('phone', '==', data.phone)
    .limit(1)
    .get();

  let uid;
  if (!usersSnap.empty) {
    uid = usersSnap.docs[0].id; // مستخدم قديم — نفس الـ uid دايمًا، بكل جهاز وكل جلسة
  } else {
    uid = db.collection('users').doc().id; // uid جديد محجوز، البروفايل الكامل ينشئ من التطبيق
  }

  const customToken = await admin.auth().createCustomToken(uid);

  await docRef.update({
    status: 'verified',
    verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
    uid,
    customToken,
  });

  console.log(`Verified: ${fromNumber} → uid: ${uid}`);
}

/// يستخرج أول رقم مكون من 6 أرقام متتالية من نص الرسالة
function extractCode(text) {
  const match = text.match(/\b\d{6}\b/);
  return match ? match[0] : null;
}


const crypto = require('crypto');

// ============================================================
// ============ إنشاء وفحص طلبات توثيق الهاتف ============
// ============================================================

app.post('/createVerification', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'phone مطلوب' });

    const id = String(phone).replace('+', '').trim();
    const code = crypto.randomInt(100000, 999999).toString();

    await db.collection('phone_verifications').doc(id).set({
      phone,
      code,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(
        new Date(Date.now() + 15 * 60 * 1000)
      ),
      uid: null,
      customToken: null,
    });

    res.json({ code });
  } catch (err) {
    console.error('createVerification error:', err);
    res.status(500).json({ error: 'حدث خطأ' });
  }
});

app.get('/verificationStatus/:phone/:code', async (req, res) => {
  try {
    const id = String(req.params.phone).replace('+', '').trim();
    const { code } = req.params;

    const doc = await db.collection('phone_verifications').doc(id).get();
    if (!doc.exists) return res.status(403).json({ error: 'غير صحيح' });

    const data = doc.data();
    if (data.code !== code) return res.status(403).json({ error: 'غير صحيح' });

    const expiresAt = data.expiresAt?.toDate?.();
    if (data.status === 'pending' && expiresAt && new Date() > expiresAt) {
      await doc.ref.update({ status: 'expired' });
      return res.json({ status: 'expired' });
    }

    if (data.status === 'verified') {
      return res.json({ status: 'verified', customToken: data.customToken });
    }

    return res.json({ status: data.status });
  } catch (err) {
    console.error('verificationStatus error:', err);
    res.status(500).json({ error: 'حدث خطأ' });
  }
});

// endpoint بسيط لإبقاء السيرفر صاحي عبر cron-job.org
app.get('/ping', (req, res) => res.send('OK'));

// endpoint للتأكد ان السيرفر شغال
app.get('/', (req, res) => res.send('WhatsApp Webhook Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
