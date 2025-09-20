// server.js — Pague Leve Checkout (Pagar.me v5) — Pix, Boleto e Cartão
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const morgan = require("morgan");
const { randomUUID, createHmac } = require("crypto");
const path = require("path");
require("dotenv").config();

const app = express();
app.set("trust proxy", 1);

// ===== Feature flags / env =====
const ENFORCE_TOTAL =
  String(process.env.ENFORCE_TOTAL_CENTS || "").toLowerCase() === "1" ||
  String(process.env.ENFORCE_TOTAL_CENTS || "").toLowerCase() === "true";

const NODE_ENV = process.env.NODE_ENV || "production";
const CHECKOUT_BASE = process.env.CHECKOUT_BASE_URL || "https://checkout.pagueleve.com";

// Pagar.me / pagamentos
const STATEMENT_DESCRIPTOR = (process.env.STATEMENT_DESCRIPTOR || "PAGUELEVE").slice(0, 13);
const PIX_EXPIRES_IN = Math.max(60, parseInt(process.env.PIX_EXPIRES_IN || "1800", 10)); // >= 60s
const BOLETO_DAYS = Math.max(1, parseInt(process.env.BOLETO_DAYS || "3", 10)); // >= 1 dia

// Rate limits
const RATE_LIMIT_GLOBAL = Math.max(60, parseInt(process.env.RATE_LIMIT_GLOBAL || "300", 10));
const RATE_LIMIT_PAY = Math.max(30, parseInt(process.env.RATE_LIMIT_PAY || "60", 10));

// Logs
const LOG_FORMAT = process.env.LOG_FORMAT || "combined";

// ===== Shopify (opcional) =====
const SHOP_DOMAIN   = process.env.SHOPIFY_STORE_DOMAIN || "";
const SHOP_VERSION  = process.env.SHOPIFY_API_VERSION || "2024-04";
const SHOP_TOKEN    = process.env.SHOPIFY_API_TOKEN || "";
const PROXY_PREFIX  = process.env.APP_PROXY_PREFIX  || "apps/cobrax";
const PROXY_SUBPATH = process.env.APP_PROXY_SUBPATH || "checkout";

// ===== Webhook signing (opcional) =====
const WH_SECRET = process.env.PAGARME_WEBHOOK_SECRET || "";
const WH_HEADER = (process.env.PAGARME_WEBHOOK_HEADER || "").toLowerCase();
const WH_ALGO   = (process.env.PAGARME_WEBHOOK_ALGO || "sha256").toLowerCase();

// ===== Body parsers =====
// raw body APENAS no webhook
app.use("/webhook", express.raw({ type: "*/*" }));
// JSON no resto
app.use((req, res, next) => {
  if (req.path === "/webhook") return next();
  return express.json({ limit: "1mb", type: "*/*" })(req, res, next);
});
// (opcional) aceitar forms clássicos também
app.use(express.urlencoded({ extended: true }));

// ===== Segurança / Perf / Logs =====
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(compression());
app.use(morgan(LOG_FORMAT));

// ===== CORS — allowlist seguro (Shopify + seus domínios) =====
const DEFAULT_ALLOWED = ['https://pagueleve.com','https://checkout.pagueleve.com'];
const EXTRA_ALLOWED = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);
const ALLOWED_ORIGINS = [...new Set([...DEFAULT_ALLOWED, ...EXTRA_ALLOWED])];

const corsOpts = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // curl / server-to-server
    try {
      const u = new URL(origin);
      const ok =
        ALLOWED_ORIGINS.includes(origin) ||
        /\.myshopify\.com$/.test(u.hostname);
      return cb(ok ? null : new Error('CORS blocked'), ok);
    } catch {
      return cb(new Error('CORS blocked'), false);
    }
  },
  credentials: false
};
app.use(cors(corsOpts));

// ===== Rate limits =====
app.use(rateLimit({ windowMs: 60_000, max: RATE_LIMIT_GLOBAL, standardHeaders: true, legacyHeaders: false }));

// ===== NO-CACHE para HTML (evitar HTML antigo) =====
app.use((req, res, next) => {
  const wantsHTML = req.method === 'GET' && (req.headers.accept || '').includes('text/html');
  if (wantsHTML) {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// ===== Helpers =====
async function shopifyAdmin(pathApi, method = "GET", body = null, extraHeaders = {}) {
  if (!SHOP_DOMAIN || !SHOP_TOKEN) throw new Error("Shopify não configurado");
  const url = `https://${SHOP_DOMAIN}/admin/api/${SHOP_VERSION}/${pathApi}`;
  const headers = { "X-Shopify-Access-Token": SHOP_TOKEN, "Content-Type": "application/json", ...extraHeaders };
  const opts = { url, method, headers, timeout: 20000 };
  if (body) opts.data = body;
  return axios(opts);
}
const onlyDigits = (s) => (s ? String(s).replace(/\D/g, "") : "");

// Conversão robusta BRL -> centavos (fallback legado)
function brlToCents(v) {
  if (v == null) return 0;
  if (typeof v === "number") return Math.max(0, Math.round(v * 100));
  const s = String(v).trim();
  if (/^\d{4,}$/.test(s)) return Math.max(0, parseInt(s, 10)); // já em cents
  const n = Number(s.replace(/\./g, "").replace(",", "."));
  return Number.isFinite(n) ? Math.max(0, Math.round(n * 100)) : 0;
}

function authHeader() {
  const key = process.env.PAGARME_API_KEY || "";
  return "Basic " + Buffer.from(`${key}:`).toString("base64");
}
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || req.ip || req.socket.remoteAddress || "")
    .toString().split(",")[0].trim();
}
async function fetchOrder(orderId) {
  const resp = await axios.get(`https://api.pagar.me/core/v5/orders/${orderId}`, {
    headers: { Authorization: authHeader() },
    timeout: 15000,
  });
  return resp.data;
}
const hasPixFields = (tx) =>
  !!(tx?.qr_code || tx?.qr_code_text || tx?.emv || tx?.qr_code_url || tx?.image_url || tx?.qr_code_base64);
function hasBoletoFields(tx, charge) {
  const url  = tx?.url || tx?.pdf?.url || tx?.pdf_url || charge?.url || charge?.pdf?.url || null;
  const line = tx?.line || tx?.line_code || charge?.line || charge?.line_code || null;
  return !!(url || line);
}
async function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
async function waitChargeReady(orderId, kind){
  const check = (tx, charge) => (kind === "pix" ? hasPixFields(tx) : hasBoletoFields(tx, charge));
  let tries = 0, delay = 600;
  while (tries < 6) {
    const order = await fetchOrder(orderId);
    const charge = order.charges?.[0];
    const tx = charge?.last_transaction || {};
    if (check(tx, charge)) return { order, charge, tx };
    await sleep(delay);
    delay = Math.min(delay * 1.6, 3000);
    tries++;
  }
  const order = await fetchOrder(orderId);
  return { order, charge: order.charges?.[0] || null, tx: order.charges?.[0]?.last_transaction || null };
}

// ==== Auditoria opcional de items_b64 (apenas visual) ====
function safeDecodeItemsB64(b64url) {
  if (!b64url) return [];
  try {
    const b64 = String(b64url).replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const raw = Buffer.from(b64 + pad, 'base64').toString('utf8');
    return JSON.parse(raw);
  } catch { return []; }
}
function subtotalFromItems(items = []) {
  return items.reduce((acc, it) => {
    const q = Number(it?.quantity || 1);
    const unit = Number(it?.price_cents || 0);
    const line = Number(it?.line_price_cents || (unit * q));
    return acc + (Number.isFinite(line) ? line : 0);
  }, 0);
}

// ===== UI / SPA =====
const PUB = path.join(__dirname, "public");
app.use(express.static(PUB, { index: false }));
app.get(["/", "/checkout"], (_req, res) => res.sendFile(path.join(PUB, "index.html")));

// ===== App Proxy (Shopify, opcional) =====
app.get(`/${PROXY_PREFIX}/${PROXY_SUBPATH}`, async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const target = qs ? `${CHECKOUT_BASE}?${qs}` : CHECKOUT_BASE;
    return res.redirect(302, target);
  } catch (e) {
    console.error("proxy error:", e.message);
    return res.status(500).send("Proxy error");
  }
});

// ===== Helper: criar pedido pendente na Shopify =====
async function createShopifyPendingOrder({
  email,
  name,
  phoneDigits,
  billing_address,
  shipping,
  uiItems,
  amountFinal,
  amountOriginal,
  coupon,
  pagarmeOrderId,
  pagarmeChargeId,
  paymentMethod
}) {
  if (!SHOP_DOMAIN || !SHOP_TOKEN) {
    console.warn("Shopify não configurado — pulando criação do pedido.");
    return { created: false, reason: "missing_credentials" };
  }

  let line_items = [];
  if (Array.isArray(uiItems) && uiItems.length) {
    line_items = uiItems.map(it => ({
      title: it.title || "Produto",
      quantity: Math.max(1, Number(it.quantity || it.qty || 1)),
      price: ((Number(it.price_cents || 0) / 100) || 0).toFixed(2)
    }));
  } else {
    line_items = [{
      title: "Pedido Pague Leve",
      quantity: 1,
      price: (Number(amountFinal || amountOriginal || 0) / 100).toFixed(2)
    }];
  }

  const shopifyBilling = {
    address1: billing_address?.line_1 || "",
    address2: billing_address?.line_2 || "",
    zip:      billing_address?.zip_code || "",
    city:     billing_address?.city || "",
    province: billing_address?.state || "",
    country:  "BR",
    name:     name || "",
    phone:    phoneDigits || ""
  };
  const shopifyShipping = {
    address1: shipping?.address?.line_1 || "",
    address2: "",
    zip:      shipping?.address?.zip_code || "",
    city:     shipping?.address?.city || "",
    province: shipping?.address?.state || "",
    country:  "BR",
    name:     name || "",
    phone:    phoneDigits || ""
  };

  const orderPayload = {
    order: {
      email,
      line_items,
      financial_status: "pending",
      billing_address: shopifyBilling,
      shipping_address: shopifyShipping,
      send_receipt: true,
      tags: ["Pagarme", "PagueLeve", (paymentMethod || "UNKNOWN").toUpperCase()].join(", "),
      note: `Checkout Pague Leve — aguardando pagamento (${paymentMethod})`,
      note_attributes: [
        { name: "pagarme_order_id",  value: pagarmeOrderId || "" },
        { name: "pagarme_charge_id", value: pagarmeChargeId || "" },
        { name: "payment_method",    value: paymentMethod || "" },
        { name: "original_amount_cents", value: String(amountOriginal || 0) },
        { name: "final_amount_cents",    value: String(amountFinal || amountOriginal || 0) },
        { name: "coupon", value: coupon || "" }
      ]
    }
  };

  const resp = await shopifyAdmin("orders.json", "POST", orderPayload);
  const shopifyOrderId = resp?.data?.order?.id;
  console.log("🟡 Shopify: pedido pendente criado:", shopifyOrderId);
  return { created: true, shopify_order_id: shopifyOrderId };
}

// ===== APIs auxiliares =====
app.get("/api/checkout-start", (req, res) => {
  const cart_id = String(req.query.cart_id || "").trim();
  const total_raw = String(req.query.total_cents || "").trim();
  const total_cents = Number.parseInt(total_raw, 10);
  if (!cart_id || Number.isNaN(total_cents))
    return res.status(400).json({ ok: false, error: "Missing params", got: { cart_id, total_raw } });
  return res.status(200).json({ ok: true, step: "checkout:start", cart_id, total_cents });
});
app.post("/api/coupon-check", async (req, res) => {
  try {
    const { code, total_cents, method } = req.body || {};
    const amount = Math.max(1, Number(total_cents || 0));
    const coup = evaluateCoupon({ code, amount_cents: amount, method: String(method || "pix").toLowerCase() });
    if (!coup.ok) return res.json({ ok:false, reason: coup.reason || "inválido" });
    const discount_cents = coup.discount_cents || 0;
    const final_amount_cents = Math.max(1, amount - discount_cents);
    const pct = coup.pct ?? Math.round(100 * discount_cents / amount);
    return res.json({
      ok: true,
      label: coup.label || "",
      discount_percent: pct,
      discount_cents,
      final_amount_cents
    });
  } catch (e) {
    return res.status(500).json({ ok:false, error: e.message || "Falha no coupon-check" });
  }
});

// ===== STEP 1: /checkout -> escolhe método e despacha p/ /pay =====
app.post('/checkout', async (req, res) => {
  try {
    const {
      name, email, cpf, phone,
      total_cents, value_cents,
      items_b64, cart_id, coupon
    } = req.body || {};

    const amount = Number(value_cents || total_cents || 0);
    if (!name || !email || !cpf || !phone || amount <= 0) {
      return res.status(400).json({ error: 'Dados insuficientes' });
    }

    const allowBoleto = amount >= 1000;
    const html = `
<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Escolha o pagamento</title>
<style>
  body{font-family:system-ui,Arial,sans-serif;background:#f3f4f6;margin:0;padding:24px}
  .card{max-width:520px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,.06);padding:20px}
  .title{font-weight:700;margin:0 0 8px 0}
  .row{display:flex;gap:8px;margin-top:12px}
  button{flex:1;padding:12px 16px;border-radius:10px;border:1px solid #e5e7eb;background:#111827;color:#fff;cursor:pointer}
  button.sec{background:#fff;color:#111;border:1px solid #e5e7eb}
  .tiny{color:#6b7280;font-size:12px;margin-top:6px}
  input,select{width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;margin-top:8px}
</style>
</head><body>
<div class="card">
  <h2 class="title">Pagar R$ ${(amount/100).toFixed(2).replace('.',',')}</h2>
  <div class="tiny">Escolha o método de pagamento</div>

  <div class="row">
    <button id="btnPix">Pix</button>
    <button id="btnBoleto" class="sec" ${allowBoleto ? '' : 'disabled style="opacity:.5;cursor:not-allowed"'}>Boleto</button>
  </div>

  <details style="margin-top:14px">
    <summary style="cursor:pointer">Cartão de crédito</summary>
    <div style="margin-top:10px">
      <input id="card_number" placeholder="Número do cartão (sem espaços)" inputmode="numeric" />
      <div class="row" style="margin-top:8px">
        <input id="exp_month" placeholder="Mês (MM)" inputmode="numeric" />
        <input id="exp_year" placeholder="Ano (AAAA)" inputmode="numeric" />
        <input id="cvv" placeholder="CVV" inputmode="numeric" />
      </div>
      <select id="installments" style="margin-top:8px">
        <option value="1" selected>1x</option>
        <option value="2">2x</option>
        <option value="3">3x</option>
        <option value="4">4x</option>
        <option value="5">5x</option>
        <option value="6">6x</option>
      </select>
      <button id="btnCard" style="margin-top:10px">Pagar com cartão</button>
    </div>
  </details>

  <div class="tiny">Ao continuar, você concorda com os termos de pagamento.</div>
</div>

<script>
  const payloadBase = ${JSON.stringify({
    name: '', email: '', cpf: '', phone: '',
    total_cents: 0, items_b64: items_b64 || null, cart_id: cart_id || null, coupon: coupon || null
  })};
  payloadBase.name  = ${JSON.stringify(name)};
  payloadBase.email = ${JSON.stringify(email)};
  payloadBase.cpf   = ${JSON.stringify(cpf)};
  payloadBase.phone = ${JSON.stringify(phone)};
  payloadBase.total_cents = ${amount};

  async function pay(method, extra={}) {
    const btn = document.activeElement;
    if (btn) { btn.disabled = true; btn.textContent = 'Processando...'; }
    try {
      const resp = await fetch('/pay', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ ...payloadBase, method, ...extra })
      });
      const data = await resp.json();

      if (!resp.ok || data.success === false) {
        alert('Falha no pagamento: ' + (data.error || resp.status));
        if (btn) { btn.disabled = false; btn.textContent = btn.id==='btnCard'?'Pagar com cartão':btn.textContent.includes('Pix')?'Pix':'Boleto'; }
        return;
      }

      if (method === 'pix' && data.pix) {
        const txt = data.pix.qr_code || '';
        const img = data.pix.qr_code_base64 ? 'data:image/png;base64,'+data.pix.qr_code_base64 : null;
        document.open(); document.write(\`
          <div style="font-family:system-ui;padding:24px">
            <h2>Pix</h2>
            \${img ? '<img src="\'+img+\'" style="max-width:260px"/>' : ''}
            <pre style="white-space:pre-wrap;background:#f3f4f6;padding:12px;border-radius:8px">\${txt}</pre>
            <div>Status: \${data.pix.status || 'pendente'}</div>
          </div>\`); document.close();
        return;
      }

      if (method === 'boleto' && data.boleto) {
        const url  = data.boleto.url;
        const line = data.boleto.line;
        document.open(); document.write(\`
          <div style="font-family:system-ui;padding:24px">
            <h2>Boleto</h2>
            \${url ? '<p><a href="\'+url+\'" target="_blank">Abrir boleto/PDF</a></p>' : ''}
            \${line ? '<pre style="white-space:pre-wrap;background:#f3f4f6;padding:12px;border-radius:8px">'+line+'</pre>' : ''}
            <div>Status: \${data.boleto.status || 'pendente'}</div>
          </div>\`); document.close();
        return;
      }

      if (method === 'card') {
        document.open(); document.write(\`
          <div style="font-family:system-ui;padding:24px">
            <h2>Cartão</h2>
            <div>Status: \${(data.card && data.card.status) || data.data?.charge_status || 'processado'}</div>
            \${data.card?.acquirer_message ? '<div>Mensagem: '+data.card.acquirer_message+'</div>' : ''}
          </div>\`); document.close();
        return;
      }

      location.reload();
    } catch (e) {
      alert('Falha de rede: ' + e.message);
      if (btn) { btn.disabled = false; }
    }
  }

  document.getElementById('btnPix').onclick = () => pay('pix');
  const btnBol = document.getElementById('btnBoleto');
  if (btnBol && !btnBol.disabled) btnBol.onclick = () => pay('boleto');

  document.getElementById('btnCard').onclick = () => {
    const number = document.getElementById('card_number').value.replace(/\\s+/g,'');
    const exp_month = document.getElementById('exp_month').value;
    const exp_year  = document.getElementById('exp_year').value;
    const cvv       = document.getElementById('cvv').value;
    const installments = document.getElementById('installments').value || '1';
    pay('card', { card_number:number, exp_month, exp_year, cvv, installments });
  };
</script>
</body></html>
    `.trim();

    return res.json({ html });
  } catch (e) {
    console.error('POST /checkout error', e);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

// ===== /pay (com ENFORCE_TOTAL_CENTS) =====
const payLimiter = rateLimit({ windowMs: 60_000, max: RATE_LIMIT_PAY, standardHeaders: true, legacyHeaders: false });
app.post("/pay", payLimiter, async (req, res) => {
  try {
    if (!process.env.PAGARME_API_KEY) {
      return res.status(500).json({ success: false, error: "PAGARME_API_KEY ausente no .env" });
    }

    const ENFORCE = ENFORCE_TOTAL;

    const {
      name, email, cpf, phone,
      method,
      card_number, exp_month, exp_year, cvv,
      installments, address, coupon,
      total_cents, items_b64
    } = req.body || {};

    if (!name || !email)  return res.status(400).json({ success: false, error: "Nome e e-mail são obrigatórios." });
    if (!method)          return res.status(400).json({ success: false, error: "Informe a forma de pagamento." });

    // Valor original (sempre do carrinho)
    let amountOriginal = 0;
    const forcedCents = Number.parseInt(total_cents, 10);

    if (ENFORCE) {
      if (!Number.isFinite(forcedCents) || forcedCents < 100) {
        return res.status(400).json({
          success: false,
          error: "total_cents ausente ou inválido. Reabra o checkout a partir do carrinho da loja."
        });
      }
      amountOriginal = forcedCents;
    } else {
      amountOriginal = Number.isFinite(forcedCents) && forcedCents >= 100
        ? forcedCents
        : Math.max(1, brlToCents(req.body.amountBRL || "1"));
    }

    // Cupom
    let discountValue = 0;
    let pct = 0;
    if (coupon) {
      const coup = evaluateCoupon({
        code: coupon,
        amount_cents: amountOriginal,
        method: String(method || "pix").toLowerCase()
      });
      if (!coup.ok) return res.status(400).json({ success:false, error:`Cupom inválido: ${coup.reason}` });
      discountValue = coup.discount_cents || 0;
      pct = coup.pct ?? Math.round(100 * discountValue / amountOriginal);
    }
    const amountFinal = Math.max(1, amountOriginal - discountValue);

    if (method === "card") {
      const parc = Math.max(1, Number(installments || 1));
      const per  = Math.floor(amountFinal / parc);
      if (per < 100) return res.status(400).json({ success:false, error:"Cada parcela precisa ser ≥ R$ 1,00." });
    }
    if (method === "boleto" && amountFinal < 1000) {
      return res.status(400).json({ success:false, error:"Valor mínimo para boleto é R$ 10,00." });
    }

    // documentos & contato
    const cpfDigits = onlyDigits(cpf);
    if (cpfDigits.length !== 11) return res.status(400).json({ success: false, error: "CPF inválido. Use 11 dígitos." });

    const phoneDigits = onlyDigits(phone || "");
    if (phoneDigits.length < 10 || phoneDigits.length > 11)
      return res.status(400).json({ success: false, error: "Celular inválido. Use DDD + número (10 ou 11 dígitos)." });
    const area_code = phoneDigits.slice(0, 2);
    const phoneNumber = phoneDigits.slice(2);

    const cepDigits = onlyDigits(address?.cep || "");
    if (address && cepDigits && cepDigits.length !== 8) {
      return res.status(400).json({ success:false, error:"CEP inválido (8 dígitos)." });
    }

    const ip = clientIp(req);
    const ua = req.headers["user-agent"] || "";

    const customer = {
      name,
      email,
      type: "individual",
      document: cpfDigits,
      tax_id: cpfDigits,
      documents: [{ type: "cpf", number: cpfDigits }],
      phones: { mobile_phone: { country_code: "55", area_code, number: phoneNumber } },
      ip,
    };

    const billing_address = {
      line_1: `${address?.address1 || ''}${address?.number ? ', ' + address.number : ''}`.trim(),
      line_2: address?.complement || '',
      zip_code: cepDigits || '00000000',
      neighborhood: address?.neighborhood || '',
      city: address?.city || '',
      state: address?.state || '',
      country: "BR"
    };

    const shipping = {
      name,
      description: "Entrega padrão",
      fee: 0,
      address: {
        line_1: billing_address.line_1,
        zip_code: billing_address.zip_code,
        city: billing_address.city,
        state: billing_address.state,
        country: "BR"
      }
    };

    // Auditoria opcional do resumo visual vindo da loja (se enviado)
    let uiItems = [];
    let uiSubtotal = 0;
    try {
      uiItems = safeDecodeItemsB64(items_b64 || '');
      uiSubtotal = subtotalFromItems(uiItems);
    } catch { /* ignore */ }
    const subtotalMismatch = Math.abs((uiSubtotal || 0) - amountOriginal);
    const hasMismatch = Number.isFinite(subtotalMismatch) && subtotalMismatch > 50; // > R$0,50
    if (hasMismatch) {
      console.warn('⚠️ subtotal(items_b64) ≠ total_cents', {
        uiSubtotal, amountOriginal, diff_cents: subtotalMismatch
      });
    }

    const commonMetadata = {
      ua, ip,
      coupon: coupon || null,
      discount_percent: pct,
      discount_amount_cents: discountValue,
      original_amount_cents: amountOriginal,
      final_amount_cents: amountFinal,
      ui_subtotal_cents: uiSubtotal || null,
      ui_subtotal_mismatch_cents: hasMismatch ? subtotalMismatch : 0
    };

    const items = [{
      code: "SKU-PAGUELEVE-001",
      name: "Pedido Pague Leve",
      description: "Checkout Pague Leve",
      quantity: 1,
      amount: amountFinal
    }];

    // pagamentos
    let payments = [];
    if (method === "pix") {
      payments = [{ payment_method: "pix", pix: { expires_in: PIX_EXPIRES_IN }, metadata: commonMetadata }];
    } else if (method === "boleto") {
      const due = new Date(Date.now() + BOLETO_DAYS * 24 * 60 * 60 * 1000).toISOString();
      payments = [{ payment_method: "boleto", boleto: { due_at: due, instructions: "Pague até o vencimento." }, metadata: commonMetadata }];
    } else if (method === "card") {
      if (!card_number || !exp_month || !exp_year || !cvv)
        return res.status(400).json({ success: false, error: "Dados do cartão incompletos." });
      const cardInstallments = Math.max(1, Number(installments || 1));
      payments = [{
        payment_method: "credit_card",
        credit_card: {
          capture: true,
          installments: cardInstallments,
          statement_descriptor: STATEMENT_DESCRIPTOR,
          card: {
            number: String(card_number).replace(/\s+/g, ""),
            exp_month: Number(exp_month),
            exp_year: Number(exp_year),
            cvv: String(cvv),
            holder: { name }
          },
          holder_document: cpfDigits,
          billing_address,
          metadata: commonMetadata
        }
      }];
    } else {
      return res.status(400).json({ success: false, error: "Método inválido." });
    }

    // cria ordem no Pagar.me
    const payload = { customer, items, payments, closed: true, shipping, metadata: commonMetadata };
    const headers = { Authorization: authHeader(), "Content-Type": "application/json", "Idempotency-Key": randomUUID() };

    const create = await axios.post("https://api.pagar.me/core/v5/orders", payload, { headers, timeout: 30000 });
    let order = create.data;
    let charge = order.charges?.[0];
    let tx = charge?.last_transaction || {};

    console.log("🧾 Order:", order.id, "| método:", method, "| valor_final_cents:", amountFinal);

    // polling pra pegar QR/linha digitável
    if (method === "pix" || method === "boleto") {
      const result = await waitChargeReady(order.id, method);
      order = result.order; charge = result.charge; tx = result.tx || {};
    }

    // tenta baixar QR base64 se só tiver URL
    let qrCodeBase64 = tx?.qr_code_base64 || null;
    if (method === "pix" && !qrCodeBase64 && tx?.qr_code_url) {
      try {
        const qrResp = await axios.get(tx.qr_code_url, { headers: { Authorization: authHeader() }, responseType: "arraybuffer", timeout: 15000 });
        qrCodeBase64 = Buffer.from(qrResp.data).toString("base64");
      } catch (e) { console.warn("⚠️ Falha ao baixar QR base64:", e?.response?.status || e.message); }
    }

    // 🔶 CRIA PEDIDO PENDENTE NA SHOPIFY (não bloqueia o retorno ao front)
    try {
      await createShopifyPendingOrder({
        email,
        name,
        phoneDigits,
        billing_address,
        shipping,
        uiItems,
        amountFinal,
        amountOriginal,
        coupon,
        pagarmeOrderId: order?.id || "",
        pagarmeChargeId: charge?.id || "",
        paymentMethod: method
      });
    } catch (e) {
      console.warn("Shopify: falha ao criar pedido pendente:", e?.response?.data || e.message);
    }

    // resposta
    const out = {
      success: true,
      data: {
        order_id: order.id,
        status: order.status,
        charge_status: charge?.status || null,
        charge_id: charge?.id || null,
        transaction_id: tx?.id || null,
        original_amount_cents: amountOriginal,
        discount_percent: pct,
        discount_amount_cents: discountValue,
        final_amount_cents: amountFinal,
        ui_subtotal_cents: uiSubtotal || null,
        ui_subtotal_mismatch_cents: hasMismatch ? subtotalMismatch : 0
      }
    };
    if (method === "pix") out.pix = {
      qr_code: tx.qr_code || tx.qr_code_text || tx.emv || null,
      qr_code_url: tx.qr_code_url || tx.image_url || null,
      qr_code_base64: qrCodeBase64 || tx.qr_code_base64 || null,
      status: tx.status || charge?.status || order.status || null
    };
    if (method === "boleto") out.boleto = {
      url: tx?.url || tx?.pdf?.url || tx?.pdf_url || charge?.url || charge?.pdf?.url || null,
      line: tx?.line || tx?.line_code || charge?.line || charge?.line_code || null,
      status: tx?.status || charge?.status || order?.status || null
    };
    if (method === "card") out.card = {
      status: tx?.status || charge?.status || order?.status || null,
      acquirer_message: tx?.acquirer_message || null,
      acquirer_tid: tx?.acquirer_tid || null,
      code: tx?.gateway_response?.code || null,
      reason: tx?.gateway_response?.errors?.[0]?.message || null
    };

    return res.json(out);
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data;
    console.error("❌ Erro Pagar.me:", { status, message: data?.message || err.message, errors: data?.errors });
    return res.status(status).json({ success: false, error: data?.message || err.message || "Falha ao processar pagamento", details: data?.errors });
  }
});

// ===== Webhook (opcional -> Shopify) =====
function verifyWebhook(req) {
  if (!WH_SECRET || !WH_HEADER) return true;
  try {
    const headerVal = (req.headers[WH_HEADER] || "").toString();
    if (!headerVal) return false;
    const raw = req.body instanceof Buffer ? req.body : Buffer.from(req.body || "");
    const hmac = createHmac(WH_ALGO, WH_SECRET).update(raw).digest("hex");
    const token = headerVal.includes("=") ? headerVal.split("=").pop() : headerVal;
    return token && hmac && token.trim().toLowerCase() === hmac.toLowerCase();
  } catch {
    return false;
  }
}
app.post("/webhook", async (req, res) => {
  try {
    if (!verifyWebhook(req)) {
      console.warn("⚠️ Assinatura de webhook inválida");
      return res.sendStatus(200);
    }
    const json = (() => {
      try { return JSON.parse(req.body.toString("utf8") || "{}"); }
      catch { return {}; }
    })();

    // 🔸 Futuro: localizar pedido Shopify e marcar como paid
    return res.sendStatus(200);
  } catch (e) {
    console.error("webhook error:", e?.response?.data || e.message);
    return res.sendStatus(200);
  }
});

// ===== util =====
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/order/:id", async (req, res) => {
  try {
    const order = await fetchOrder(req.params.id);
    const charge = order.charges?.[0]; const tx = charge?.last_transaction || {};
    res.json({ success: true, data: {
      order_id: order.id,
      order_status: order.status,
      charge_status: charge?.status || null,
      transaction_status: tx?.status || null,
      method: charge?.payment_method || tx?.payment_method || null
    } });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || "Falha ao consultar order" });
  }
});
app.post("/refund", async (req, res) => {
  try {
    const { charge_id, amount } = req.body || {};
    if (!charge_id) return res.status(400).json({ success: false, error: "charge_id é obrigatório" });
    const r = await axios.post(`https://api.pagar.me/core/v5/charges/${charge_id}/cancel`, amount ? { amount } : {}, { headers: { Authorization: authHeader() }, timeout: 15000 });
    res.json({ success: true, data: r.data });
  } catch (e) {
    res.status(e.response?.status || 500).json({ success: false, error: e.response?.data?.message || e.message });
  }
});

// SPA fallback
const PUB_DIR = path.join(__dirname, "public");
app.get(/^\/(?!api\/|pay$|webhook$|order\/|refund$|confirm$).*/, (_req, res) => {
  res.sendFile(path.join(PUB_DIR, "index.html"));
});
app.use("/api", (_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🟢 Server on :${PORT} | ENFORCE_TOTAL_CENTS=${ENFORCE_TOTAL} | NODE_ENV=${NODE_ENV} | RL(global=${RATE_LIMIT_GLOBAL}/min, pay=${RATE_LIMIT_PAY}/min)`)
);

// ===== Coupons (fonte da verdade no back) =====
function evaluateCoupon({ code, amount_cents, method }) {
  const coupon = String(code || "").trim().toUpperCase();
  const m = String(method || "pix").toLowerCase();
  const amt = Math.max(0, Number(amount_cents || 0));

  if (!coupon) return { ok: false, reason: "cupom vazio" };
  if (amt < 100) return { ok: false, reason: "valor muito baixo" };

  if (coupon === "NATAL10") {
    const pct = 10;
    return { ok: true, pct, discount_cents: Math.floor((pct/100)*amt), label: "10% OFF" };
  }
  if (coupon === "PIX5") {
    if (m !== "pix") return { ok:false, reason: "válido somente para Pix" };
    const pct = 5;
    return { ok: true, pct, discount_cents: Math.floor((pct/100)*amt), label: "5% OFF (Pix)" };
  }
  if (coupon === "PRIMEIRA") {
    const pct = 15;               // 15% com teto de R$30
    const cap = 3000;
    const bruto = Math.floor((pct/100)*amt);
    return { ok:true, pct, discount_cents: Math.min(bruto, cap), label: "15% OFF (até R$30)" };
  }
  if (coupon === "DESCONTO100") {
    const discount_cents = Math.min(amt - 100, 1000000); // deixa final ~R$1
    if (discount_cents <= 0) return { ok:false, reason:"valor já mínimo" };
    return { ok:true, pct: Math.round(100*discount_cents/amt), discount_cents, label:"valor simbólico" };
  }

  return { ok: false, reason: "cupom não encontrado" };
}
