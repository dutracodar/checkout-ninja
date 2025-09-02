// server.js — Cobrax Checkout (Pagar.me v5) — Pix, Boleto e Cartão
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
app.set("trust proxy", 1); // Render/NGINX

/* =========================
   COBRAX <-> SHOPIFY BRIDGE
   ========================= */
const SHOP_DOMAIN   = process.env.SHOPIFY_STORE_DOMAIN;
const SHOP_VERSION  = process.env.SHOPIFY_API_VERSION || "2024-04";
const SHOP_TOKEN    = process.env.SHOPIFY_API_TOKEN;
const PROXY_PREFIX  = process.env.APP_PROXY_PREFIX  || "apps/cobrax";
const PROXY_SUBPATH = process.env.APP_PROXY_SUBPATH || "checkout";
const CHECKOUT_BASE = process.env.CHECKOUT_BASE_URL || "https://checkout.pagueleve.com";

/* =========================
   Webhook signing (opcional)
   Se a Pagar.me fornecer segredo + header, preencha:
   - PAGARME_WEBHOOK_SECRET
   - PAGARME_WEBHOOK_HEADER (ex.: "x-hub-signature" ou "x-pagarme-signature")
   - PAGARME_WEBHOOK_ALGO   (ex.: "sha256")
   ========================= */
const WH_SECRET = process.env.PAGARME_WEBHOOK_SECRET || "";
const WH_HEADER = (process.env.PAGARME_WEBHOOK_HEADER || "").toLowerCase();
const WH_ALGO   = (process.env.PAGARME_WEBHOOK_ALGO || "sha256").toLowerCase();

// Captura raw body SÓ para /webhook (precisa p/ assinatura)
app.use("/webhook", express.raw({ type: "*/*" }));
// Demais rotas em JSON
app.use((req, res, next) => {
  if (req.path === "/webhook") return next();
  express.json({ limit: "1mb", type: "*/*" })(req, res, next);
});
app.use(express.urlencoded({ extended: true }));

// -------- middlewares base --------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("combined"));
// Deixa aberto por enquanto; dá pra restringir depois
app.use(cors());
app.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false }));

// ---------- helpers ----------
async function shopifyAdmin(pathApi, method = "GET", body = null, extraHeaders = {}) {
  const url = `https://${SHOP_DOMAIN}/admin/api/${SHOP_VERSION}/${pathApi}`;
  const headers = { "X-Shopify-Access-Token": SHOP_TOKEN, "Content-Type": "application/json", ...extraHeaders };
  const opts = { method, headers, timeout: 20000 };
  if (body) opts.data = body;
  return axios({ url, ...opts });
}
const onlyDigits = (s) => (s ? String(s).replace(/\D/g, "") : "");
function brlToCents(v) {
  if (v == null) return 0;
  if (typeof v === "number") return Math.round(v * 100);
  const n = Number(String(v).replace(/\./g, "").replace(",", "."));
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
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

/* =========================
   UI (SPA)
   ========================= */
const PUB = path.join(__dirname, "public");
app.use(express.static(PUB));
app.get(["/", "/checkout"], (_req, res) => res.sendFile(path.join(PUB, "index.html")));

/* =========================
   App Proxy -> redireciona pro Cobrax (quando usar proxy oficial)
   ========================= */
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

/* =========================
   Shopify order creation helper (reuso no webhook e /confirm)
   ========================= */
async function createShopifyPaidOrderFromPagarmePayload(body) {
  const charges = body?.charges || body?.data?.charges || [];
  const charge  = charges[0] || body?.charge || {};
  const tx      = charge?.last_transaction || {};
  const status  = (tx?.status || charge?.status || body?.status || "").toLowerCase();
  const isPaid = ["paid", "succeeded", "captured", "approved"].includes(status);
  if (!isPaid) return { created: false, reason: "not_paid" };

  const amountCents = Number(charge?.amount || body?.amount || 0);
  const amountBRL   = (amountCents / 100).toFixed(2);
  const buyerEmail  = body?.customer?.email || body?.customer?.address?.email || "cliente@exemplo.com";
  const buyerName   = body?.customer?.name  || "Cliente Cobrax";

  // Tenta ler itens do metadata
  let metaItemsRaw = charge?.metadata?.items ?? body?.metadata?.items ?? body?.items;
  let parsedItems = [];
  try {
    if (Array.isArray(metaItemsRaw)) parsedItems = metaItemsRaw;
    else if (typeof metaItemsRaw === "string") parsedItems = JSON.parse(metaItemsRaw);
  } catch {}

  // Fallback 1 item
  let lineItems = [{ title: "Pedido Cobrax", quantity: 1, price: amountBRL }];

  if (parsedItems.length > 0) {
    lineItems = parsedItems.map(it => ({
      title: it.title || it.sku || "Item",
      quantity: Number(it.qty || it.quantity || 1),
      price: ((Number(it.price_cents ?? 0)) / 100).toFixed(2),
      sku: it.sku || undefined,
    }));
  }

  const noteAttrs = [];
  const orderId = body?.id || body?.order?.id || body?.data?.id;
  const txId    = tx?.id;
  const statusTag = status || "";
  if (orderId)    noteAttrs.push({ name: "pagarme_order_id", value: String(orderId) });
  if (charge?.id) noteAttrs.push({ name: "pagarme_charge_id", value: String(charge.id) });
  if (txId)       noteAttrs.push({ name: "pagarme_tx_id", value: String(txId) });
  if (statusTag)  noteAttrs.push({ name: "pagarme_status", value: statusTag });

  // endereço de entrega (se vier no payload)
  const shipping_address = body?.shipping ? {
    first_name: buyerName,
    address1: body.shipping.address?.line_1 || '',
    address2: body.shipping.address?.line_2 || '',
    city: body.shipping.address?.city || '',
    province: body.shipping.address?.state || '',
    country: 'Brazil',
    country_code: 'BR',
    zip: body.shipping.address?.zip_code || '',
    phone: onlyDigits(body?.customer?.phones?.mobile_phone?.number || "") || undefined
  } : undefined;

  const shopifyOrder = {
    order: {
      email: buyerEmail,
      send_receipt: false,
      send_fulfillment_receipt: false,
      financial_status: "paid",
      currency: "BRL",
      note: `Pagar.me order ${orderId} / charge ${charge?.id || ""}`,
      note_attributes: noteAttrs,
      line_items: lineItems,
      customer: { first_name: buyerName, email: buyerEmail },
      shipping_address,
      tags: "cobrax,pagarme",
    },
  };

  const idem = `pagarme-${orderId}-${charge?.id || "nocharge"}`;
  const r = await shopifyAdmin("orders.json", "POST", shopifyOrder, { "Idempotency-Key": idem });
  return { created: true, shopify_order_id: r.data?.order?.id || null };
}

/* =========================
   API — inicia o fluxo
   ========================= */
app.get("/api/checkout-start", (req, res) => {
  const cart_id = String(req.query.cart_id || "").trim();
  const total_raw = String(req.query.total_cents || "").trim();
  const total_cents = Number.parseInt(total_raw, 10);
  if (!cart_id || Number.isNaN(total_cents))
    return res.status(400).json({ ok: false, error: "Missing params", got: { cart_id, total_raw } });
  return res.status(200).json({ ok: true, step: "checkout:start", cart_id, total_cents });
});

/* =========================
   /pay — cria ordem no Pagar.me (PIX / Boleto / Cartão)
   ========================= */
app.post("/pay", async (req, res) => {
  try {
    if (!process.env.PAGARME_API_KEY)
      return res.status(500).json({ success: false, error: "PAGARME_API_KEY ausente no .env" });

    const {
      name, email, cpf, phone,
      method,               // "pix" | "boleto" | "card"
      amountBRL,
      card_number, exp_month, exp_year, cvv,
      installments,         // nº parcelas
      address               // { cep, address1, number, complement, neighborhood, city, state }
    } = req.body || {};

    if (!name || !email)  return res.status(400).json({ success: false, error: "Nome e e-mail são obrigatórios." });
    if (!method)          return res.status(400).json({ success: false, error: "Informe a forma de pagamento." });

    const amount = Math.max(1, brlToCents(amountBRL || "1"));
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

    // IMPORTANTE: descrição exigida pelo v5 (evita 422 'order.shipping.description')
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

    // item simples
    const items = [{
      code: "SKU-COBRAX-001",
      name: "Pedido Cobrax",
      description: "Checkout Cobrax",
      quantity: 1,
      amount
    }];

    let payments = [];
    if (method === "pix") {
      payments = [{ payment_method: "pix", pix: { expires_in: 1800 }, metadata: { ua, ip } }];
    } else if (method === "boleto") {
      const due = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
      payments = [{ payment_method: "boleto", boleto: { due_at: due, instructions: "Pague até o vencimento." }, metadata: { ua, ip } }];
    } else if (method === "card") {
      if (!card_number || !exp_month || !exp_year || !cvv)
        return res.status(400).json({ success: false, error: "Dados do cartão incompletos." });
      const cardInstallments = Math.max(1, Number(installments || 1));
      payments = [{
        payment_method: "credit_card",
        credit_card: {
          capture: true,
          installments: cardInstallments, // PARCELAS
          statement_descriptor: "COBRAX",
          card: {
            number: String(card_number).replace(/\s+/g, ""),
            exp_month: Number(exp_month),
            exp_year: Number(exp_year),
            cvv: String(cvv),
            holder: { name }
          },
          holder_document: cpfDigits,
          billing_address,
          metadata: { ua, ip }
        }
      }];
    } else {
      return res.status(400).json({ success: false, error: "Método inválido." });
    }

    const payload = { customer, items, payments, closed: true, shipping };
    const headers = { Authorization: authHeader(), "Content-Type": "application/json", "Idempotency-Key": randomUUID() };

    // cria order
    const create = await axios.post("https://api.pagar.me/core/v5/orders", payload, { headers, timeout: 30000 });
    let order = create.data;
    let charge = order.charges?.[0];
    let tx = charge?.last_transaction || {};

    console.log("🧾 Order:", order.id, "| método:", method);

    // polling (pix/boleto)
    if (method === "pix" || method === "boleto") {
      const result = await waitChargeReady(order.id, method);
      order = result.order; charge = result.charge; tx = result.tx || {};
    }

    // tenta obter QR base64 se vier só URL
    let qrCodeBase64 = tx?.qr_code_base64 || null;
    if (method === "pix" && !qrCodeBase64 && tx?.qr_code_url) {
      try {
        const qrResp = await axios.get(tx.qr_code_url, { headers: { Authorization: authHeader() }, responseType: "arraybuffer", timeout: 15000 });
        qrCodeBase64 = Buffer.from(qrResp.data).toString("base64");
      } catch (e) { console.warn("⚠️ Falha ao baixar QR base64:", e?.response?.status || e.message); }
    }

    const out = {
      success: true,
      data: { order_id: order.id, status: order.status, charge_status: charge?.status || null, charge_id: charge?.id || null, transaction_id: tx?.id || null }
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

/* =========================
   WEBHOOK Pagar.me -> cria pedido na Shopify quando pago
   ========================= */
function verifyWebhook(req) {
  if (!WH_SECRET || !WH_HEADER) return true; // verificação desativada
  try {
    const headerVal = (req.headers[WH_HEADER] || "").toString();
    if (!headerVal) return false;
    const raw = req.body instanceof Buffer ? req.body : Buffer.from(req.body || "");
    const hmac = createHmac(WH_ALGO, WH_SECRET).update(raw).digest("hex");
    // formatos possíveis: "sha256=abcdef..." ou só "abcdef..."
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
      return res.sendStatus(200); // responde 200 pra não gerar retries infinitos
    }
    const json = (() => {
      try { return JSON.parse(req.body.toString("utf8") || "{}"); }
      catch { return {}; }
    })();

    const result = await createShopifyPaidOrderFromPagarmePayload(json);
    if (result.created) console.log("✅ Pedido criado na Shopify:", result.shopify_order_id);
    else console.log("Webhook recebido, ainda não pago.");
    return res.sendStatus(200);
  } catch (e) {
    console.error("webhook->shopify error:", e?.response?.data || e.message);
    return res.sendStatus(200);
  }
});

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Consulta order
app.get("/order/:id", async (req, res) => {
  try {
    const order = await fetchOrder(req.params.id);
    const charge = order.charges?.[0]; const tx = charge?.last_transaction || {};
    res.json({ success: true, data: { order_id: order.id, order_status: order.status, charge_status: charge?.status || null, transaction_status: tx?.status || null, method: charge?.payment_method || tx?.payment_method || null } });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || "Falha ao consultar order" });
  }
});

// Refund/cancel
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

/* =========================
   Plano B: confirmar manualmente quando status virar "paid"
   ========================= */
app.post("/confirm", express.json(), async (req, res) => {
  try {
    const { order_id } = req.body || {};
    if (!order_id) return res.status(400).json({ ok:false, error:"order_id é obrigatório" });

    const order = await fetchOrder(order_id);
    const charge = order.charges?.[0];
    const tx = charge?.last_transaction || {};
    const status = (tx?.status || charge?.status || order?.status || "").toLowerCase();

    const paid = ["paid","succeeded","captured","approved"].includes(status);
    if (!paid) return res.status(200).json({ ok:true, paid:false, status });

    const payload = { id: order.id, status: order.status, charges: [ { ...charge, last_transaction: tx } ], customer: order.customer || {}, shipping: order.shipping || undefined };
    const result = await createShopifyPaidOrderFromPagarmePayload(payload);
    return res.status(200).json({ ok:true, paid:true, created: result.created, shopify_order_id: result.shopify_order_id || null });
  } catch (e) {
    console.error("/confirm error:", e?.response?.data || e.message);
    return res.status(500).json({ ok:false, error: e.message || "Falha no confirm" });
  }
});

/* =========================
   Fallback SPA — depois de TODAS as APIs
   ========================= */
app.get(/^\/(?!api\/|pay$|webhook$|order\/|refund$|confirm$).*/, (_req, res) => {
  res.sendFile(path.join(PUB, "index.html"));
});

// 404 apenas para APIs (não quebra SPA/UI)
app.use("/api", (_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`🟢 Server on :${PORT}`));
