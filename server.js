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
app.disable("x-powered-by");
app.set("trust proxy", 1);

// ===== Feature flags / env =====
const ENFORCE_TOTAL =
  String(process.env.ENFORCE_TOTAL_CENTS || "").toLowerCase() === "1" ||
  String(process.env.ENFORCE_TOTAL_CENTS || "").toLowerCase() === "true";

// ===== Shopify (opcional) =====
const SHOP_DOMAIN   = process.env.SHOPIFY_STORE_DOMAIN || "";
const SHOP_VERSION  = process.env.SHOPIFY_API_VERSION || "2024-04";
const SHOP_TOKEN    = process.env.SHOPIFY_API_TOKEN || "";
const PROXY_PREFIX  = process.env.APP_PROXY_PREFIX  || "apps/cobrax";
const PROXY_SUBPATH = process.env.APP_PROXY_SUBPATH || "checkout";
const CHECKOUT_BASE = process.env.CHECKOUT_BASE_URL || "https://checkout.pagueleve.com";

// ===== Webhook signing (opcional) =====
const WH_SECRET = process.env.PAGARME_WEBHOOK_SECRET || "";
const WH_HEADER = (process.env.PAGARME_WEBHOOK_HEADER || "").toLowerCase();
const WH_ALGO   = (process.env.PAGARME_WEBHOOK_ALGO || "sha256").toLowerCase();

// ---------- Segurança & infra ----------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("combined"));

// CORS (aceita *.myshopify.com e seus domínios)
const ALLOW_ORIGINS = [
  "https://pagueleve.com",
  "https://checkout.pagueleve.com"
];
const ORIGIN_REGEX = [/^https:\/\/([a-z0-9-]+\.)*myshopify\.com$/i];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOW_ORIGINS.includes(origin) || ORIGIN_REGEX.some(r => r.test(origin))) {
      return cb(null, true);
    }
    return cb(new Error("CORS blocked"), false);
  }
}));
app.options("*", cors());

app.use(rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
}));

// raw body só no webhook
app.use("/webhook", express.raw({ type: "*/*" }));
// json no resto
app.use((req, res, next) => {
  if (req.path === "/webhook") return next();
  express.json({ limit: "1mb", type: "*/*" })(req, res, next);
});
app.use(express.urlencoded({ extended: true }));

// Não deixe respostas de API em cache
app.use((req, res, next) => {
  if (req.method !== "GET" || req.path.startsWith("/api") || req.path === "/pay") {
    res.set("Cache-Control", "no-store");
  }
  next();
});

// ===== helpers =====
async function shopifyAdmin(pathApi, method = "GET", body = null, extraHeaders = {}) {
  if (!SHOP_DOMAIN || !SHOP_TOKEN) throw new Error("Shopify não configurado");
  const url = `https://${SHOP_DOMAIN}/admin/api/${SHOP_VERSION}/${pathApi}`;
  const headers = { "X-Shopify-Access-Token": SHOP_TOKEN, "Content-Type": "application/json", ...extraHeaders };
  const opts = { method, headers, timeout: 20000 };
  if (body) opts.data = body;
  return axios({ url, ...opts });
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
    .toString()
    .split(",")[0]
    .trim();
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

// ===== UI / SPA =====
const PUB = path.join(__dirname, "public");

// estáticos: cache longo para assets, NO-STORE para HTML
app.use(express.static(PUB, {
  index: false,
  etag: true,
  lastModified: true,
  setHeaders(res, filePath) {
    const isHtml = /\.html?$/i.test(filePath);
    if (isHtml || path.basename(filePath) === "index.html") {
      res.setHeader("Cache-Control", "no-store");
    } else {
      res.setHeader("Cache-Control", "public, max-age=2592000, immutable"); // 30d
    }
  }
}));

app.get(["/", "/checkout"], (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(PUB, "index.html"));
});

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

// ===== APIs =====
app.get("/api/checkout-start", (req, res) => {
  const cart_id = String(req.query.cart_id || "").trim();
  const total_raw = String(req.query.total_cents || "").trim();
  const total_cents = Number.parseInt(total_raw, 10);
  if (!cart_id || Number.isNaN(total_cents))
    return res.status(400).json({ ok: false, error: "Missing params", got: { cart_id, total_raw } });
  return res.status(200).json({ ok: true, step: "checkout:start", cart_id, total_cents });
});

// sempre em centavos
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

// ===== /pay (com ENFORCE_TOTAL_CENTS) =====
app.post("/pay", async (req, res) => {
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
      total_cents
    } = req.body || {};

    // validações básicas
    if (!name || !email)  return res.status(400).json({ success: false, error: "Nome e e-mail são obrigatórios." });
    if (!method)          return res.status(400).json({ success: false, error: "Informe a forma de pagamento." });

    // -------- VALOR ORIGINAL (prioriza carrinho; obrigatório com ENFORCE) --------
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
      if (Number.isFinite(forcedCents) && forcedCents >= 100) {
        amountOriginal = forcedCents;
      } else {
        amountOriginal = Math.max(1, brlToCents(req.body.amountBRL || "1")); // legado
      }
    }

    // -------- CUPOM --------
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

    // mínimos (opcionais)
    if (method === "card") {
      const parc = Math.max(1, Number(installments || 1));
      const per  = Math.floor(amountFinal / parc);
      if (per < 100) return res.status(400).json({ success:false, error:"Cada parcela precisa ser ≥ R$ 1,00." });
    }
    if (method === "boleto" && amountFinal < 1000) {
      return res.status(400).json({ success:false, error:"Valor mínimo para boleto é R$ 10,00." });
    }

    // documentos & contato
    const only = onlyDigits;
    const cpfDigits = only(cpf);
    if (cpfDigits.length !== 11) return res.status(400).json({ success: false, error: "CPF inválido. Use 11 dígitos." });

    const phoneDigits = only(phone || "");
    if (phoneDigits.length < 10 || phoneDigits.length > 11)
      return res.status(400).json({ success: false, error: "Celular inválido. Use DDD + número (10 ou 11 dígitos)." });
    const area_code = phoneDigits.slice(0, 2);
    const phoneNumber = phoneDigits.slice(2);

    const cepDigits = only(address?.cep || "");
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

    const commonMetadata = {
      ua, ip,
      coupon: coupon || null,
      discount_percent: pct,
      discount_amount_cents: discountValue,
      original_amount_cents: amountOriginal,
      final_amount_cents: amountFinal
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
      payments = [{ payment_method: "pix", pix: { expires_in: 1800 }, metadata: commonMetadata }];
    } else if (method === "boleto") {
      const due = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
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
          statement_descriptor: "PAGUELEVE",
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
        final_amount_cents: amountFinal
      }
    };
    if (method === "pix") out.pix = { qr_code: tx.qr_code || tx.qr_code_text || tx.emv || null, qr_code_url: tx.qr_code_url || tx.image_url || null, qr_code_base64: qrCodeBase64 || tx.qr_code_base64 || null, status: tx.status || charge?.status || order.status || null };
    if (method === "boleto") out.boleto = { url: tx?.url || tx?.pdf?.url || tx?.pdf_url || charge?.url || charge?.pdf?.url || null, line: tx?.line || tx?.line_code || charge?.line || charge?.line_code || null, status: tx?.status || charge?.status || order?.status || null };
    if (method === "card") out.card = { status: tx?.status || charge?.status || order?.status || null, acquirer_message: tx?.acquirer_message || null, acquirer_tid: tx?.acquirer_tid || null, code: tx?.gateway_response?.code || null, reason: tx?.gateway_response?.errors?.[0]?.message || null };

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

    // opcional: criar pedido na Shopify quando pago
    // const result = await createShopifyPaidOrderFromPagarmePayload(json);
    // if (result.created) console.log("✅ Pedido criado na Shopify:", result.shopify_order_id);
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
    res.json({ success: true, data: { order_id: order.id, order_status: order.status, charge_status: charge?.status || null, transaction_status: tx?.status || null, method: charge?.payment_method || tx?.payment_method || null } });
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

// SPA fallback (qualquer rota não-API serve o index)
app.get(/^\/(?!api\/|pay$|webhook$|order\/|refund$|confirm$).*/, (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(PUB, "index.html"));
});
app.use("/api", (_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`🟢 Server on :${PORT} | ENFORCE_TOTAL_CENTS=${ENFORCE_TOTAL}`)
);
