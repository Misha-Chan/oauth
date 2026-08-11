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
// نفس القيمة الافتراضية بالمشروع الرئيسي (server.js) — يُفضَّل ضبط نفس
// القيمة الحقيقية بمتغير البيئة JWT_SECRET بكلا المشروعين بالإنتاج.
const JWT_SECRET = process.env.JWT_SECRET || 'hostaka-secret-2026';
// نطاقات مسموح لها تسأل عن التوكن (CORS + قبول الكوكي عبر النطاقات الفرعية)
const ALLOWED_ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)?hostaka\.fun$/i;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '.hostaka.fun';
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 يوم

app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(cookieParser());
app.use(express.json({ limit: '64kb' }));

// ============================================================
// CORS يدوي — لازم نعكس الـ Origin بالضبط (مو *) عشان نقدر نستخدم
// Access-Control-Allow-Credentials مع الكوكي
// ============================================================
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGIN_RE.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// التحقق من توقيع التوكن اختياري (معطّل افتراضياً) — فعّله بضبط
// VERIFY_TOKENS=1 + نفس قيمة JWT_SECRET الحقيقية المستخدمة بمشروع
// hostaka-main بالضبط. تفعيله بالغلط بقيمة سر مختلفة عن المشروع
// الرئيسي يكسر الوسيط بالكامل بصمت (كل توكن حقيقي يُرفض كـ"غير صالح")،
// فالافتراضي تخزين آمن بسيط بدون تحقق توقيع، والتحقق الملزم الحقيقي
// يبقى دائماً على hostaka.fun نفسه (كل طلب API يمر بـ requireAuth هناك).
const VERIFY_TOKENS = process.env.VERIFY_TOKENS === '1';
function looksLikeValidToken(token) {
  if (typeof token !== 'string' || token.length < 10 || token.length > 4096) return false;
  if (!VERIFY_TOKENS || !jwt) return true;
  try { jwt.verify(token, JWT_SECRET); return true; }
  catch (e) { return false; }
}

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
