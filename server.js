const express = require('express');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

// تحميل بيانات حساب الخدمة (Service Account) من متغير بيئة
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
      const fromNumber = msg.from; // رقم المرسل بدون +
      const docRef = db.collection('phone_verifications').doc(fromNumber);
      const doc = await docRef.get();

      if (doc.exists && doc.data()?.status === 'pending') {
        await docRef.update({
          status: 'verified',
          verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        console.log(`Verified: ${fromNumber}`);
      } else {
        console.log(`No pending verification for: ${fromNumber}`);
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook error:', err);
    // دايماً رجّع 200 لواتساب حتى لو صار خطأ داخلي، وإلا يعيد المحاولة بشكل مزعج
    res.sendStatus(200);
  }
});

// endpoint بسيط لإبقاء السيرفر صاحي عبر cron-job.org
app.get('/ping', (req, res) => res.send('OK'));

// endpoint للتأكد ان السيرفر شغال
app.get('/', (req, res) => res.send('WhatsApp Webhook Server is running'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
