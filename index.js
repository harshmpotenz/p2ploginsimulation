import express from "express";
import fetch from "node-fetch";
import axios from "axios";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cookieParser());

const SHOPIFY_STORE = process.env.SHOPIFY_STORE;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || "https://p2ploginsimulation.onrender.com";
const MULTIPASS_SECRET = process.env.SHOPIFY_MULTIPASS_SECRET;

// Dummy in-memory store (replace with DB)
const userStore = new Map(); // email -> { shopifyCustomerId, password }

app.get("/auth/google", (req, res) => {
  const redirect = `https://accounts.google.com/o/oauth2/v2/auth?` +
    new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: `${BASE_URL}/auth/google/callback`,
      response_type: "code",
      scope: "openid email profile",
      prompt: "select_account"
    });

  res.redirect(redirect);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send("Google did not return an authorization code");
  }

  // Exchange code for token
  const tokenBody = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    code: String(code),
    redirect_uri: `${BASE_URL}/auth/google/callback`,
    grant_type: "authorization_code"
  });

  const tokenRes = await axios.post("https://oauth2.googleapis.com/token", tokenBody.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  const { access_token } = tokenRes.data;

  // Get profile
  const profileRes = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${access_token}` }
  });

  const { email, given_name, family_name } = profileRes.data;

  if (MULTIPASS_SECRET) {
    const multipassUrl = buildMultipassUrl({
      email,
      firstName: given_name,
      lastName: family_name,
      returnTo: "/account"
    });

    return res.redirect(multipassUrl);
  }

  // 1) Ensure Shopify customer exists
  let user = userStore.get(email);
  if (!user) {
    const password = crypto.randomBytes(16).toString("hex");
    const customer = await createOrFindCustomer(email, given_name, family_name, password);

    user = { shopifyCustomerId: customer.id, password };
    userStore.set(email, user);
  }

  // 2) Do server-side Shopify login
  const cookies = await shopifyServerLogin(email, user.password);

  // 3) Forward cookies to browser
  cookies.forEach((cookie) => {
    res.append("Set-Cookie", cookie);
  });

  res.redirect(`https://${SHOPIFY_STORE}/account`);
});

async function createOrFindCustomer(email, firstName, lastName, password) {
  const searchRes = await axios.get(
    `https://${SHOPIFY_STORE}/admin/api/2024-01/customers/search.json?query=email:${email}`,
    { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
  );

  if (searchRes.data.customers.length > 0) {
    const existing = searchRes.data.customers[0];

    // Always reset password so we know what it is
    await axios.put(
      `https://${SHOPIFY_STORE}/admin/api/2024-01/customers/${existing.id}.json`,
      { customer: { id: existing.id, password, password_confirmation: password } },
      { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
    );

    return existing;
  }

  const createRes = await axios.post(
    `https://${SHOPIFY_STORE}/admin/api/2024-01/customers.json`,
    {
      customer: {
        email,
        first_name: firstName,
        last_name: lastName,
        password,
        password_confirmation: password,
        verified_email: true,
        status: "enabled"
      }
    },
    { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
  );

  return createRes.data.customer;
}

function extractAuthenticityToken(html) {
  const inputPattern = /<input[^>]*name=["']authenticity_token["'][^>]*>/i;
  const inputTag = html.match(inputPattern)?.[0];

  if (inputTag) {
    const valueMatch = inputTag.match(/value=["']([^"']+)["']/i);
    if (valueMatch?.[1]) {
      return valueMatch[1];
    }
  }

  const loosePattern = /name=["']authenticity_token["'][^>]*value=["']([^"']+)["']/i;
  const looseMatch = html.match(loosePattern);
  if (looseMatch?.[1]) {
    return looseMatch[1];
  }

  const reversedPattern = /value=["']([^"']+)["'][^>]*name=["']authenticity_token["']/i;
  const reversedMatch = html.match(reversedPattern);
  if (reversedMatch?.[1]) {
    return reversedMatch[1];
  }

  return null;
}

function detectBotChallenge(html) {
  const challengeSignals = [
    "captcha",
    "challenge",
    "hcaptcha",
    "recaptcha",
    "cf-chl",
    "verify you are human"
  ];

  const normalized = html.toLowerCase();
  return challengeSignals.some((signal) => normalized.includes(signal));
}



function toBase64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function buildMultipassUrl({ email, firstName, lastName, returnTo = "/account" }) {
  if (!MULTIPASS_SECRET) {
    throw new Error("Missing SHOPIFY_MULTIPASS_SECRET for Multipass login");
  }

  const keyMaterial = crypto.createHash("sha256").update(MULTIPASS_SECRET).digest();
  const encryptionKey = keyMaterial.subarray(0, 16);
  const signatureKey = keyMaterial.subarray(16, 32);

  const payload = {
    email,
    first_name: firstName,
    last_name: lastName,
    return_to: `https://${SHOPIFY_STORE}${returnTo}`,
    created_at: new Date().toISOString()
  };

  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-128-cbc", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const ciphertext = Buffer.concat([iv, encrypted]);

  const signature = crypto.createHmac("sha256", signatureKey).update(ciphertext).digest();
  const token = toBase64Url(Buffer.concat([ciphertext, signature]));

  return `https://${SHOPIFY_STORE}/account/login/multipass/${token}`;
}
async function shopifyServerLogin(email, password) {
  // Step 1: GET login page to obtain session cookies and optional authenticity_token
  const loginPageRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      Accept: "text/html"
    },
    redirect: "manual"
  });

  const initialCookies = loginPageRes.headers.raw()["set-cookie"] || [];
  const cookieHeader = initialCookies.map((cookie) => cookie.split(";")[0]).join("; ");

  // Extract authenticity_token from HTML (if the theme renders one)
  const html = await loginPageRes.text();
  const authenticityToken = extractAuthenticityToken(html);

  if (!authenticityToken) {
    if (detectBotChallenge(html)) {
      throw new Error(
        "Shopify login page appears to be protected by a bot challenge/CAPTCHA. Server-side login cannot continue until that protection is bypassed for this endpoint."
      );
    }

    console.warn("No authenticity_token found on /account/login; attempting legacy login without token.");
  }

  // Step 2: POST login. On many legacy stores token may be optional.
  const body = new URLSearchParams();
  body.append("form_type", "customer_login");
  body.append("utf8", "✓");
  if (authenticityToken) {
    body.append("authenticity_token", authenticityToken);
  }
  body.append("return_to", "/account");
  body.append("customer[email]", email);
  body.append("customer[password]", password);

  const loginRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "Mozilla/5.0",
      Referer: `https://${SHOPIFY_STORE}/account/login`,
      Cookie: cookieHeader
    },
    body,
    redirect: "manual"
  });

  // A successful login normally redirects away from /account/login
  const location = loginRes.headers.get("location") || "";
  if (location.includes("/account/login")) {
    throw new Error("Shopify login failed — still redirected to /account/login (credentials, account state, or theme challenge issue)");
  }

  const loginCookies = loginRes.headers.raw()["set-cookie"] || [];
  if (loginCookies.length === 0) {
    throw new Error("Shopify login did not return session cookies. Check if your theme/apps block server-side logins.");
  }

  return loginCookies.map((cookie) => {
    if (cookie.toLowerCase().includes("domain=")) {
      return cookie.replace(/Domain=[^;]+/i, `Domain=.${SHOPIFY_STORE}`);
    }
    return `${cookie}; Domain=.${SHOPIFY_STORE}`;
  });
}

app.listen(3000, () => {
  console.log("Auth server running on port 3000");
});
