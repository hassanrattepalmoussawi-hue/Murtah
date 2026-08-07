const express = require('express');
const admin = require('firebase-admin');

const app = express();
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

// endpoint بسيط لإبقاء السيرفر صاحي عبر cron-job.org
app.get('/ping', (req, res) => res.send('OK'));

// endpoint للتأكد ان السيرفر شغال
app.get('/', (req, res) => res.send('WhatsApp Webhook Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
