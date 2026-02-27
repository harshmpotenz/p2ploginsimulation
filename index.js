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
const BASE_URL = "https://p2ploginsimulation.onrender.com"; // your EC2 domain

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
  if (!code) return res.status(400).send("No code");

  // Exchange code for token
  const tokenRes = await axios.post("https://oauth2.googleapis.com/token", {
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    code,
    redirect_uri: `${BASE_URL}/auth/google/callback`,
    grant_type: "authorization_code"
  });

  const { access_token } = tokenRes.data;

  // Get profile
  const profileRes = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${access_token}` }
  });

  const { email, given_name, family_name } = profileRes.data;

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
  cookies.forEach(c => {
    res.append("Set-Cookie", c);
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

    // ✅ Always reset password so we know what it is
    await axios.put(
      `https://${SHOPIFY_STORE}/admin/api/2024-01/customers/${existing.id}.json`,
      { customer: { id: existing.id, password, password_confirmation: password } },
      { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
    );

    return existing;
  }
 const createRes = await axios.post(`https://${SHOPIFY_STORE}/admin/api/2024-01/customers.json`,
    {
      customer: {
        email,
        first_name: firstName,
        last_name: lastName,
        password,
        password_confirmation: password,
        verified_email: true,
        status  : "enabled"
        
      }
    },
    { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
  );
    return createRes.data.customer;

}


async function shopifyServerLogin(email, password) {
  // Step 1: GET login page to obtain session cookies AND authenticity_token
  const loginPageRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    headers: {
      "User-Agent": "Mozilla/5.0",
      "Accept": "text/html",
    }
  });

  const initialCookies = loginPageRes.headers.raw()["set-cookie"] || [];
  const cookieHeader = initialCookies.map(c => c.split(";")[0]).join("; ");

  // ✅ Extract authenticity_token from the HTML
  const html = await loginPageRes.text();
  const tokenMatch = html.match(/name="authenticity_token"\s+value="([^"]+)"/);
  if (!tokenMatch) {
    throw new Error("Could not find authenticity_token on Shopify login page");
  }
  const authenticityToken = tokenMatch[1];

  console.log("Found authenticity_token:", authenticityToken);

  // Step 2: POST login WITH authenticity_token
  const body = new URLSearchParams();
  body.append("form_type", "customer_login");
  body.append("utf8", "✓");
  body.append("authenticity_token", authenticityToken); // ✅ added
  body.append("return_to", "/account");
  body.append("customer[email]", email);
  body.append("customer[password]", password);

  const loginRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": "Mozilla/5.0",
      "Referer": `https://${SHOPIFY_STORE}/account/login`, // ✅ added
      "Cookie": cookieHeader
    },
    body,
    redirect: "manual"
  });

  console.log("LOGIN RESPONSE STATUS:", loginRes.status);

  // ✅ A successful login returns 302 to /account, failed returns 302 to /account/login
  const location = loginRes.headers.get("location");
  console.log("Redirect location:", location);

  if (location && location.includes("/account/login")) {
    throw new Error("Shopify login failed — wrong credentials or account issue");
  }

  const loginCookies = loginRes.headers.raw()["set-cookie"] || [];

return loginCookies.map(c => {
  if (c.toLowerCase().includes("domain=")) {
    return c.replace(/Domain=[^;]+/i, `Domain=.${SHOPIFY_STORE}`);
  }
  return c + `; Domain=.${SHOPIFY_STORE}`;
});
}
app.listen(3000, () => {
  console.log("Auth server running on port 3000");
});