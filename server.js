// ============================================================
//  oauth.hostaka.fun — وسيط تحقق مركزي بين كل النطاقات الفرعية
//
//  المشكلة: localStorage غير مشترك بين hostaka.fun والنطاقات الفرعية
//  (orbithub، aethercast، console...) — كل نطاق فرعي كان يحتاج مسار
//  "تمرير توكن" يدوي (?token=) عند كل انتقال، وإذا المستخدم مسجّل دخول
//  أصلاً بالمنصة الرئيسية ويحتاج يسجّل دخول من نطاق فرعي، صفحة تسجيل
//  الدخول تكتشف إنه مسجّل مسبقاً وتوديه للصفحة الرئيسية مباشرة، بدون
//  رجوع للنطاق الفرعي اللي طلب التسجيل أصلاً.
//
//  الحل: كوكي واحد مشترك (Domain=.hostaka.fun) يشوفه كل نطاق فرعي
//  تلقائياً. هذا السيرفر يخزّن/يقرأ/يمسح هذا الكوكي فقط — ما له علاقة
//  بمنطق تسجيل الدخول نفسه (ده لسا بالكامل على hostaka.fun)، هو بس
//  "صندوق بريد" آمن ينقل التوكن بين النطاقات.
//
//  التدفق:
//  1) المستخدم يسجّل دخول بنجاح على hostaka.fun → الموقع الرئيسي يبعث
//     التوكن هنا (POST /api/token, credentials:include) فيُخزَّن بكوكي
//     مشترك.
//  2) أي نطاق فرعي، عند تحميل الصفحة وما عنده توكن محلي بـ localStorage،
//     يسأل هنا بصمت (GET /api/token, credentials:include) — المتصفح
//     يرفق الكوكي المشترك تلقائياً لأنه بنفس eTLD+1 (hostaka.fun)، حتى
//     لو النطاق الفرعي غير النطاق اللي أنشأ الكوكي أصلاً.
//  3) تسجيل الخروج من أي مكان يمسح الكوكي المشترك (DELETE /api/token)
//     عشان نطاق فرعي ثاني ما يلتقط جلسة قديمة بالغلط.
// ============================================================
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
let jwt = null;
try { jwt = require('jsonwebtoken'); } catch (e) { /* اختياري — شوف verifyTokenIfPossible بالأسفل */ }

const app = express();

const COOKIE_NAME = 'hostaka_relay';
// نطاقات مسموح لها تسأل عن التوكن (CORS + قبول الكوكي عبر النطاقات الفرعية)
const ALLOWED_ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)?hostaka\.fun$/i;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '.hostaka.fun';
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 يوم

// ============================================================
// التحقق من توقيع التوكن اختياري (معطّل افتراضياً) — فعّله بضبط
// VERIFY_TOKENS=1 + نفس قيمة JWT_SECRET الحقيقية المستخدمة بمشروع
// hostaka-main بالضبط. تفعيله بالغلط بقيمة سر مختلفة عن المشروع
// الرئيسي يكسر الوسيط بالكامل بصمت (كل توكن حقيقي يُرفض كـ"غير صالح")،
// فالافتراضي تخزين آمن بسيط بدون تحقق توقيع، والتحقق الملزم الحقيقي
// يبقى دائماً على hostaka.fun نفسه (كل طلب API يمر بـ requireAuth هناك).
//
// ملاحظة أمنية: ما فيه أي سر افتراضي مكتوب بالكود إطلاقاً. لو VERIFY_TOKENS
// مفعّل لازم JWT_SECRET يكون مضبوط بمتغير البيئة، وإلا السيرفر يرفض الإقلاع
// (بدل ما يستخدم سر معروف من المستودع العام — وهذا كان ثغرة حرجة).
// ============================================================
const VERIFY_TOKENS = process.env.VERIFY_TOKENS === '1';
const JWT_SECRET = process.env.JWT_SECRET || '';
if (VERIFY_TOKENS && (!jwt || !JWT_SECRET)) {
  throw new Error(
    'VERIFY_TOKENS=1 يتطلب: (1) تثبيت حزمة jsonwebtoken، (2) ضبط JWT_SECRET بنفس قيمة مشروع hostaka-main بالضبط.'
  );
}
if (!VERIFY_TOKENS) {
  console.warn('⚠️  VERIFY_TOKENS غير مفعّل — التوكنات تُخزَّن بدون التحقق من توقيعها (التحقق الملزم على hostaka.fun).');
}

function looksLikeValidToken(token) {
  if (typeof token !== 'string' || token.length < 10 || token.length > 4096) return false;
  if (!VERIFY_TOKENS || !jwt) return true;
  try { jwt.verify(token, JWT_SECRET); return true; }
  catch (e) { return false; }
}

function isAllowedOrigin(origin) {
  return typeof origin === 'string' && ALLOWED_ORIGIN_RE.test(origin);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json({ limit: '64kb' }));

// ============================================================
// رؤوس أمان أساسية على كل الردود.
// ============================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// ============================================================
// CORS يدوي — لازم نعكس الـ Origin بالضبط (مو *) عشان نقدر نستخدم
// Access-Control-Allow-Credentials مع الكوكي. أي نطاق غير مسموح ما يحصل
// على أي هيدر CORS، فالمتصفح يمنع قراءة الرد.
// ============================================================
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ============================================================
// حماية CSRF: العمليات التي تغيّر الحالة (POST/DELETE) لازم تجي من نطاق
// مسموح عبر هيدر Origin صريح. المتصفح يرسل Origin تلقائياً على الطلبات
// عبر-النطاقات، فنطلب تطابقه مع القائمة المسموحة. هذا يمنع محاولات
// النماذج/الطلبات من مواقع خارجية (التي إما ترسل Origin غير مسموح أو لا
// ترسله إطلاقاً).
// ============================================================
app.use((req, res, next) => {
  if (req.method === 'POST' || req.method === 'DELETE') {
    if (!isAllowedOrigin(req.headers.origin)) {
      return res.status(403).json({ error: 'مصدر الطلب غير مسموح' });
    }
  }
  next();
});

// ============================================================
// حدّ معدّل بسيط داخل العملية (in-memory) على مسار التوكن — يقلّل
// المحاولات الآلية/الاجتياح بدون أي اعتماد خارجي.
// ============================================================
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 60;
const rateBuckets = new Map();
app.use('/api/token', (req, res, next) => {
  const key = req.ip || 'unknown';
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > RATE_MAX) {
    return res.status(429).json({ error: 'طلبات كثيرة، حاول لاحقاً' });
  }
  if (rateBuckets.size > 5000) rateBuckets.clear();
  next();
});

// لا يُخزَّن أي رد لمسار التوكن في أي كاش وسيط
app.use('/api/token', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  next();
});

// ============================================================
// GET /api/token — يقرأ الكوكي المشترك ويرجّع التوكن (لو موجود)
// ============================================================
app.get('/api/token', (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(404).json({ token: null });
  res.json({ token });
});

// ============================================================
// POST /api/token — يخزّن توكن جديد بالكوكي المشترك (يُستدعى من
// hostaka.fun فور نجاح تسجيل الدخول)
// ============================================================
app.post('/api/token', (req, res) => {
  const token = req.body && req.body.token;
  if (!looksLikeValidToken(token)) {
    return res.status(400).json({ error: 'توكن غير صالح' });
  }
  res.cookie(COOKIE_NAME, token, {
    domain: COOKIE_DOMAIN,
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax', // النطاقات الفرعية لنفس hostaka.fun تُعتبر "same-site"
    maxAge: COOKIE_MAX_AGE_MS
  });
  res.json({ success: true });
});

// ============================================================
// DELETE /api/token — يمسح الكوكي المشترك (تسجيل خروج)
// ============================================================
app.delete('/api/token', (req, res) => {
  res.clearCookie(COOKIE_NAME, { domain: COOKIE_DOMAIN, path: '/' });
  res.json({ success: true });
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nDisallow: /\n');
});

app.use((req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ oauth relay running on port ${PORT} (cookie domain: ${COOKIE_DOMAIN})`));
}

module.exports = app;
