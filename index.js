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
const BASE_URL = "https://auth.yoursite.com"; // your EC2 domain

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
  // Search
  const searchRes = await axios.get(
    `https://${SHOPIFY_STORE}/admin/api/2024-01/customers/search.json?query=email:${email}`,
    { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
  );

  if (searchRes.data.customers.length > 0) {
    return searchRes.data.customers[0];
  }

  // Create
  const createRes = await axios.post(
    `https://${SHOPIFY_STORE}/admin/api/2024-01/customers.json`,
    {
      customer: {
        email,
        first_name: firstName,
        last_name: lastName,
        password,
        password_confirmation: password,
        verified_email: true
      }
    },
    { headers: { "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN } }
  );

  return createRes.data.customer;
}
async function shopifyServerLogin(email, password) {
  // Step 1: GET login page
  const loginPageRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    method: "GET",
    redirect: "manual"
  });

  const setCookies1 = loginPageRes.headers.raw()["set-cookie"] || [];
  const html = await loginPageRes.text();

  // Extract authenticity_token (simple regex, may need adjustment)
  const tokenMatch = html.match(/name="authenticity_token" value="([^"]+)"/);
  if (!tokenMatch) throw new Error("CSRF token not found");

  const authenticityToken = tokenMatch[1];

  const cookieHeader1 = setCookies1.map(c => c.split(";")[0]).join("; ");

  // Step 2: POST login
  const body = new URLSearchParams();
  body.append("form_type", "customer_login");
  body.append("utf8", "✓");
  body.append("customer[email]", email);
  body.append("customer[password]", password);
  body.append("authenticity_token", authenticityToken);

  const loginRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader1
    },
    body,
    redirect: "manual"
  });

  const setCookies2 = loginRes.headers.raw()["set-cookie"] || [];

  // Return cookies to forward to browser
  return setCookies2.map(c => {
    // Make sure domain/path are correct for your store
    return c.replace(/Domain=[^;]+;/i, `Domain=.${SHOPIFY_STORE};`);
  });
}
app.listen(3000, () => {
  console.log("Auth server running on port 3000");
});