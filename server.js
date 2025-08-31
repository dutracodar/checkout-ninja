// server.js — Cobrax Checkout (Pagar.me v5) — Pix, Boleto e Cartão + Shopify Bridge
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const morgan = require("morgan");
const { randomUUID } = require("crypto");
require("dotenv").config();

const app = express();
app.set('trust proxy', 1); // Render/NGINX na frente do Node


/* =========================
   COBRAX <-> SHOPIFY BRIDGE
   ========================= */
const SHOP_DOMAIN   = process.env.SHOPIFY_STORE_DOMAIN;   // ex: "sualoja.myshopify.com"
const SHOP_VERSION  = process.env.SHOPIFY_API_VERSION || "2024-04";
const SHOP_TOKEN    = process.env.SHOPIFY_API_TOKEN;
const PROXY_PREFIX  = process.env.APP_PROXY_PREFIX  || "apps/cobrax";
const PROXY_SUBPATH = process.env.APP_PROXY_SUBPATH || "checkout";
const CHECKOUT_BASE = process.env.CHECKOUT_BASE_URL || "https://checkout.pagueleve.com";

// Helper p/ Admin API
async function shopifyAdmin(path, method = "GET", body = null) {
  const url = `https://${SHOP_DOMAIN}/admin/api/${SHOP_VERSION}/${path}`;
  const headers = {
    "X-Shopify-Access-Token": SHOP_TOKEN,
    "Content-Type": "application/json",
  };
  const opts = { method, headers, timeout: 20000 };
  if (body) opts.data = body;
  return axios({ url, ...opts });
}

/* =========================
   Middlewares
   ========================= */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("combined"));
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

/* =========================
   Helpers
   ========================= */
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
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
    .toString().split(",")[0].trim();
}

function hasPixFields(tx) {
  return !!(tx?.qr_code || tx?.qr_code_text || tx?.emv || tx?.qr_code_url || tx?.image_url || tx?.qr_code_base64);
}

function hasBoletoFields(tx, charge) {
  const url = tx?.url || tx?.pdf?.url || tx?.pdf_url || charge?.url || charge?.pdf?.url || null;
  const line = tx?.line || tx?.line_code || charge?.line || charge?.line_code || null;
  return !!(url || line);
}

async function fetchOrder(orderId) {
  const resp = await axios.get(`https://api.pagar.me/core/v5/orders/${orderId}`, {
    headers: { Authorization: authHeader() },
    timeout: 15000,
  });
  return resp.data;
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
   2.1) APP PROXY -> redireciona p/ Cobrax
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
   /pay — cria ordem no Pagar.me
   ========================= */
app.post("/pay", async (req, res) => {
  try {
    if (!process.env.PAGARME_API_KEY) {
      return res.status(500).json({ success: false, error: "PAGARME_API_KEY ausente no .env" });
    }

    const {
      name, email, cpf, phone,
      method,                // "pix" | "boleto" | "card"
      amountBRL,             // "10,00" | "10.00" | 10
      total_cents,           // opcional: total em centavos
      // cartão:
      card_number, exp_month, exp_year, cvv,
      // itens (string JSON ou array)
      items
    } = req.body || {};

    // lê itens vindos do front
    let itemsFromClient = [];
    try {
      if (Array.isArray(items)) itemsFromClient = items;
      else if (typeof items === "string") itemsFromClient = JSON.parse(items);
    } catch (_) { itemsFromClient = []; }

    // validações
    if (!name || !email) return res.status(400).json({ success: false, error: "Nome e e-mail são obrigatórios." });
    if (!method) return res.status(400).json({ success: false, error: "Informe a forma de pagamento." });

    const centsFromClient = Number.isFinite(Number(total_cents)) ? Number(total_cents) : null;
    const amount = Math.max(1, centsFromClient != null ? centsFromClient : brlToCents(amountBRL || "1"));

    const cpfDigits = onlyDigits(cpf);
    if (cpfDigits.length !== 11) {
      return res.status(400).json({ success: false, error: "CPF inválido. Use 11 dígitos." });
    }

    const phoneDigits = onlyDigits(phone || "");
    if (phoneDigits.length < 10 || phoneDigits.length > 11) {
      return res.status(400).json({ success: false, error: "Celular inválido. Use DDD + número (10 ou 11 dígitos)." });
    }
    const area_code = phoneDigits.slice(0, 2);
    const phoneNumber = phoneDigits.slice(2);

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

    // item dummy p/ Pagar.me (ele exige pelo menos 1 item)
    const itemsForPagarme = [
      { code: "SKU-COBRAX-001", name: "Pedido Cobrax", description: "Checkout Cobrax", quantity: 1, amount },
    ];

    // payments + metadata (inclui itens do carrinho)
    let payments = [];
    if (method === "pix") {
      payments = [{
        payment_method: "pix",
        pix: { expires_in: 1800 },
        metadata: { ua, ip, items: itemsFromClient }
      }];
    } else if (method === "boleto") {
      const due = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
      payments = [{
        payment_method: "boleto",
        boleto: { due_at: due, instructions: "Pague até o vencimento." },
        metadata: { ua, ip, items: itemsFromClient }
      }];
    } else if (method === "card") {
      if (!card_number || !exp_month || !exp_year || !cvv) {
        return res.status(400).json({ success: false, error: "Dados do cartão incompletos." });
      }
      payments = [{
        payment_method: "credit_card",
        credit_card: {
          capture: true,
          installments: 1,
          statement_descriptor: "COBRAX",
          card: {
            number: String(card_number).replace(/\s+/g, ""),
            exp_month: Number(exp_month),
            exp_year: Number(exp_year),
            cvv: String(cvv),
            holder: { name }
          },
          holder_document: cpfDigits,
          billing_address: {
            line_1: "Rua Teste, 123",
            zip_code: "01311000",
            city: "São Paulo",
            state: "SP",
            country: "BR"
          },
          metadata: { ua, ip, items: itemsFromClient }
        }
      }];
    } else {
      return res.status(400).json({ success: false, error: "Método inválido." });
    }

    const payload = { customer, items: itemsForPagarme, payments, closed: true };

    // Idempotência
    const idempotencyKey = randomUUID();
    const headers = {
      Authorization: authHeader(),
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    };

    // 1) cria a order no Pagar.me
    const create = await axios.post("https://api.pagar.me/core/v5/orders", payload, { headers, timeout: 30000 });
    let order = create.data;
    let charge = order.charges?.[0];
    let tx = charge?.last_transaction || {};

    console.log("🧾 Order:", order.id, "| método:", method);

    // 2) polling p/ PIX e BOLETO
    if (method === "pix" || method === "boleto") {
      const result = await waitChargeReady(order.id, method);
      order = result.order; charge = result.charge; tx = result.tx || {};
    }

    // 3) patch para QR base64 quando vier só URL
    let qrCodeBase64 = tx?.qr_code_base64 || null;
    if (method === "pix" && !qrCodeBase64 && tx?.qr_code_url) {
      try {
        const qrResp = await axios.get(tx.qr_code_url, {
          headers: { Authorization: authHeader() },
          responseType: "arraybuffer",
          timeout: 15000,
        });
        qrCodeBase64 = Buffer.from(qrResp.data).toString("base64");
      } catch (e) {
        console.warn("⚠️ Falha ao baixar QR base64:", e?.response?.status || e.message);
      }
    }

    const out = {
      success: true,
      data: {
        order_id: order.id,
        status: order.status,
        charge_status: charge?.status || null,
        charge_id: charge?.id || null,
        transaction_id: tx?.id || null,
      },
    };

    if (method === "pix") {
      out.pix = {
        qr_code: tx.qr_code || tx.qr_code_text || tx.emv || null,
        qr_code_url: tx.qr_code_url || tx.image_url || null,
        qr_code_base64: qrCodeBase64 || tx.qr_code_base64 || null,
        status: tx.status || charge?.status || order.status || null,
      };
    }

    if (method === "boleto") {
      out.boleto = {
        url: tx?.url || tx?.pdf?.url || tx?.pdf_url || charge?.url || charge?.pdf?.url || null,
        line: tx?.line || tx?.line_code || charge?.line || charge?.line_code || null,
        status: tx?.status || charge?.status || order?.status || null,
      };
    }

    if (method === "card") {
      out.card = {
        status: tx?.status || charge?.status || order?.status || null,
        acquirer_message: tx?.acquirer_message || null,
        acquirer_tid: tx?.acquirer_tid || null,
        code: tx?.gateway_response?.code || null,
        reason: tx?.gateway_response?.errors?.[0]?.message || null
      };
    }

    return res.json(out);
  } catch (err) {
    const status = err.response?.status || 500;
    const data = err.response?.data;
    console.error("❌ Erro Pagar.me:", {
      status,
      message: data?.message || err.message,
      errors: data?.errors,
    });
    return res.status(status).json({
      success: false,
      error: data?.message || err.message || "Falha ao processar pagamento",
      details: data?.errors,
    });
  }
});

/* =========================
   /webhook — cria pedido na Shopify quando pago
   ========================= */
app.post("/webhook", express.json({ type: "*/*" }), async (req, res) => {
  try {
    const body   = req.body || {};
    const orderId = body?.id || body?.order?.id || body?.data?.id;

    const charges = body?.charges || body?.data?.charges || [];
    const charge  = charges[0] || body?.charge;
    const tx      = charge?.last_transaction || {};
    const status  = tx?.status || charge?.status || body?.status;

    const isPaid = ["paid", "succeeded", "captured", "approved"]
      .includes(String(status || "").toLowerCase());

    if (!isPaid) {
      console.log("Webhook recebido, não pago ainda:", status, "| order:", orderId);
      return res.sendStatus(200);
    }

    const amountCents = (charge?.amount || body?.amount || 0);
    const amountBRL   = (amountCents / 100).toFixed(2);

    const buyerEmail  = body?.customer?.email || body?.customer?.address?.email || "cliente@exemplo.com";
    const buyerName   = body?.customer?.name || "Cliente Cobrax";

    // ---- Reconstrói items reais (metadata -> Shopify line_items) ----
    let metaItemsRaw = charge?.metadata?.items ?? body?.metadata?.items ?? body?.items;
    let parsedItems = [];
    try {
      if (Array.isArray(metaItemsRaw)) parsedItems = metaItemsRaw;
      else if (typeof metaItemsRaw === "string") parsedItems = JSON.parse(metaItemsRaw);
    } catch (_) { parsedItems = []; }

    let lineItems = [
      { title: "Pedido Cobrax", quantity: 1, price: amountBRL }
    ];

    if (parsedItems.length > 0) {
      lineItems = parsedItems.map(it => ({
        title: it.title || it.sku || "Item",
        quantity: Number(it.qty || it.quantity || 1),
        price: ((it.price_cents ?? 0) / 100).toFixed(2),
        sku: it.sku || undefined
      }));
    }

    const shopifyOrder = {
      order: {
        email: buyerEmail,
        send_receipt: false,
        send_fulfillment_receipt: false,
        financial_status: "paid",
        note: `Pagar.me order ${orderId} / charge ${charge?.id || ""}`,
        line_items: lineItems,
        customer: { first_name: buyerName, email: buyerEmail },
        tags: "cobrax,pagarme",
      },
    };

    const r = await shopifyAdmin("orders.json", "POST", shopifyOrder);
    console.log("✅ Pedido criado na Shopify:", r.data?.order?.id);

    return res.sendStatus(200);
  } catch (e) {
    console.error("webhook->shopify error:", e?.response?.data || e.message);
    return res.sendStatus(200); // evita loop
  }
});

/* =========================
   Utilidades
   ========================= */
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/order/:id", async (req, res) => {
  try {
    const order = await fetchOrder(req.params.id);
    const charge = order.charges?.[0];
    const tx = charge?.last_transaction || {};
    res.json({
      success: true,
      data: {
        order_id: order.id,
        order_status: order.status,
        charge_status: charge?.status || null,
        transaction_status: tx?.status || null,
        method: charge?.payment_method || tx?.payment_method || null,
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || "Falha ao consultar order" });
  }
});

app.post("/refund", async (req, res) => {
  try {
    const { charge_id, amount } = req.body || {};
    if (!charge_id) return res.status(400).json({ success: false, error: "charge_id é obrigatório" });
    const r = await axios.post(
      `https://api.pagar.me/core/v5/charges/${charge_id}/cancel`,
      amount ? { amount } : {},
      { headers: { Authorization: authHeader() }, timeout: 15000 }
    );
    res.json({ success: true, data: r.data });
  } catch (e) {
    res.status(e.response?.status || 500).json({ success: false, error: e.response?.data?.message || e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🟢 Server on :${PORT}`));
