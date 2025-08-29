// server.js — Cobrax Checkout (Pagar.me v5) — Pix, Boleto e Cartão
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

// -------- middlewares base --------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan("combined"));
app.use(cors()); // como servimos front e back juntos, deixar aberto simplifica
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public")); // serve ./public (index.html)

// Rate limit defensivo
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

// ---------- helpers ----------
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
    .toString()
    .split(",")[0]
    .trim();
}

function hasPixFields(tx) {
  return !!(
    tx?.qr_code ||
    tx?.qr_code_text ||
    tx?.emv ||
    tx?.qr_code_url ||
    tx?.image_url ||
    tx?.qr_code_base64
  );
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

// Backoff simples p/ aguardar QR/linha do boleto
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

// ---------- rota principal ----------
app.post("/pay", async (req, res) => {
  try {
    if (!process.env.PAGARME_API_KEY) {
      return res.status(500).json({ success: false, error: "PAGARME_API_KEY ausente no .env" });
    }

    const {
      name, email, cpf, phone,        // DDD + número (10 ou 11 dígitos)
      method,                         // "pix" | "boleto" | "card"
      amountBRL,                      // "10,00" | "10.00" | 10
      // cartão (opcional)
      card_number, exp_month, exp_year, cvv,
    } = req.body || {};

    // validações básicas
    if (!name || !email) return res.status(400).json({ success: false, error: "Nome e e-mail são obrigatórios." });
    if (!method) return res.status(400).json({ success: false, error: "Informe a forma de pagamento." });

    const amount = Math.max(1, brlToCents(amountBRL || "1"));

    const cpfDigits = onlyDigits(cpf);
    if (cpfDigits.length !== 11) {
      return res.status(400).json({ success: false, error: "CPF inválido. Use 11 dígitos." });
    }

    const phoneDigits = onlyDigits(phone || "");
    if (phoneDigits.length < 10 || phoneDigits.length > 11) {
      return res.status(400).json({
        success: false,
        error: "Celular inválido. Use DDD + número (10 ou 11 dígitos).",
      });
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

    // item com 'code' evita falha no boleto (“The item Code is required.”)
    const items = [
      { code: "SKU-COBRAX-001", name: "Pedido Cobrax", description: "Checkout Cobrax", quantity: 1, amount },
    ];

    let payments = [];
    if (method === "pix") {
      payments = [{ payment_method: "pix", pix: { expires_in: 1800 }, metadata: { ua, ip } }]; // 30 min
    } else if (method === "boleto") {
      const due = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(); // +3 dias
      payments = [{
        payment_method: "boleto",
        boleto: { due_at: due, instructions: "Pague até o vencimento." },
        metadata: { ua, ip }
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
          metadata: { ua, ip }
        }
      }];
    } else {
      return res.status(400).json({ success: false, error: "Método inválido." });
    }

    const payload = { customer, items, payments, closed: true };

    // Idempotência evita duplicar pedidos
    const idempotencyKey = randomUUID();
    const headers = {
      Authorization: authHeader(),
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    };

    // 1) cria a order
    const create = await axios.post("https://api.pagar.me/core/v5/orders", payload, {
      headers, timeout: 30000,
    });

    let order = create.data;
    let charge = order.charges?.[0];
    let tx = charge?.last_transaction || {};

    console.log("🧾 Order:", order.id, "| método:", method);

    // 2) polling p/ PIX e BOLETO com backoff
    if (method === "pix" || method === "boleto") {
      const result = await waitChargeReady(order.id, method);
      order = result.order; charge = result.charge; tx = result.tx || {};
    }

    // --- patch: garante qr_code_base64 quando vier só a URL ---
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

    // 3) normaliza resposta pro front
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

// ---------- webhook (cadastre /webhook no dashboard) ----------
app.post("/webhook", express.json({ type: "*/*" }), (req, res) => {
  try {
    const event = req.body?.type || req.body?.event || "unknown";
    const data = req.body?.data || req.body?.payload || req.body;

    // TODO: persistir/atualizar seu DB com order/charge/tx/status
    console.log("🔔 Webhook:", JSON.stringify({
      event,
      order_id: data?.id || data?.order?.id,
      charge_id: data?.charges?.[0]?.id || data?.charge?.id,
      tx_status: data?.charges?.[0]?.last_transaction?.status,
    }, null, 2));

    res.sendStatus(200);
  } catch (e) {
    console.error("webhook error:", e);
    res.sendStatus(500);
  }
});
// Healthcheck
app.get("/health", (req, res) => res.json({ ok: true }));

// Consultar status de uma order
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

// Reembolso/cancelamento (total) por charge_id
app.post("/refund", async (req, res) => {
  try {
    const { charge_id, amount } = req.body || {};
    if (!charge_id) return res.status(400).json({ success: false, error: "charge_id é obrigatório" });
    const r = await axios.post(
      `https://api.pagar.me/core/v5/charges/${charge_id}/cancel`,
      amount ? { amount } : {}, // opcional: reembolso parcial em centavos
      { headers: { Authorization: authHeader() }, timeout: 15000 }
    );
    res.json({ success: true, data: r.data });
  } catch (e) {
    res.status(e.response?.status || 500).json({ success: false, error: e.response?.data?.message || e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🟢 Server on :${PORT}`));
