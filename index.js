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

// Dummy in-memory store 
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


<<<<<<< HEAD
async function shopifyServerLogin(email, password) {
  console.log("Starting legacy Shopify login for:", email);

  // Step 1: GET login page to obtain session cookies
  const loginPageRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
=======
function parseHiddenInputsFromCustomerLoginForm(html) {
  const formMatch = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
  const customerForm = formMatch.find((formHtml) => /name=["']form_type["'][^>]*value=["']customer_login["']/i.test(formHtml) || /action=["'][^"']*\/account\/login[^"']*["']/i.test(formHtml));

  if (!customerForm) {
    return {};
  }

  const inputMatches = customerForm.match(/<input[^>]*>/gi) || [];
  const hiddenInputs = {};

  inputMatches.forEach((inputTag) => {
    const type = inputTag.match(/type=["']([^"']+)["']/i)?.[1]?.toLowerCase();
    const name = inputTag.match(/name=["']([^"']+)["']/i)?.[1];
    const value = inputTag.match(/value=["']([^"']*)["']/i)?.[1] || "";

    if ((type === "hidden" || name === "form_type" || name === "utf8") && name) {
      hiddenInputs[name] = value;
>>>>>>> 7dad952ce2da3a385e4ba412e0c18bf0640d9732
    }
  });

  return hiddenInputs;
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
<<<<<<< HEAD
  const cookieHeader = initialCookies.map(c => c.split(";")[0]).join("; ");
  
  console.log("Initial cookies obtained:", initialCookies.length);

  // Step 2: Extract token using enhanced detection
  const html = await loginPageRes.text();
  let authenticityToken = await extractAuthenticityToken(html);

  // Step 3: If no token found, try alternative approaches
  if (!authenticityToken) {
    console.log("No authenticity_token found. Trying alternative approaches...");
    
    // Try to get token from a different endpoint
    authenticityToken = await tryAlternativeTokenExtraction(cookieHeader);
  }

  // Step 4: Prepare login form data
  const formData = new URLSearchParams();
  formData.append("form_type", "customer_login");
  formData.append("utf8", "✓");
  
  if (authenticityToken) {
    formData.append("authenticity_token", authenticityToken);
    console.log("Using authenticity_token:", authenticityToken.substring(0, 20) + "...");
  }
  
  formData.append("return_url", "/account");
  formData.append("customer[email]", email);
  formData.append("customer[password]", password);
=======
  const cookieHeader = initialCookies.map((cookie) => cookie.split(";")[0]).join("; ");

  // Extract dynamic hidden inputs from HTML so legacy themes work without strict token assumptions
  const html = await loginPageRes.text();

  if (detectBotChallenge(html)) {
    throw new Error(
      "Shopify login page appears to be protected by a bot challenge/CAPTCHA. Server-side login cannot continue until that protection is bypassed for this endpoint."
    );
  }

  const hiddenInputs = parseHiddenInputsFromCustomerLoginForm(html);
  const authenticityToken = hiddenInputs.authenticity_token || extractAuthenticityToken(html);

  // Step 2: POST login using hidden form fields found in the storefront markup
  const body = new URLSearchParams();
  Object.entries(hiddenInputs).forEach(([key, value]) => {
    body.append(key, value);
  });

  if (!body.has("form_type")) {
    body.append("form_type", "customer_login");
  }

  if (!body.has("utf8")) {
    body.append("utf8", "✓");
  }

  if (authenticityToken && !body.has("authenticity_token")) {
    body.append("authenticity_token", authenticityToken);
  }

  body.set("return_to", "/account");
  body.set("customer[email]", email);
  body.set("customer[password]", password);
>>>>>>> 7dad952ce2da3a385e4ba412e0c18bf0640d9732

  // Step 5: Submit login form
  const loginRes = await fetch(`https://${SHOPIFY_STORE}/account/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
<<<<<<< HEAD
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Referer": `https://${SHOPIFY_STORE}/account/login`,
      "Cookie": cookieHeader
=======
      "User-Agent": "Mozilla/5.0",
      Referer: `https://${SHOPIFY_STORE}/account/login`,
      Cookie: cookieHeader
>>>>>>> 7dad952ce2da3a385e4ba412e0c18bf0640d9732
    },
    body: formData,
    redirect: "manual"
  });

<<<<<<< HEAD
  console.log("Login response status:", loginRes.status);

  // Step 6: Handle response
  const location = loginRes.headers.get("location");
  console.log("Redirect location:", location);

  // Check for successful login indicators
  const setCookie = loginRes.headers.raw()["set-cookie"] || [];
  console.log("Set-Cookie headers:", setCookie.length);

  // Success criteria: redirect to /account (not /account/login)
  if (location && location.includes("/account") && !location.includes("/account/login")) {
    console.log("Login successful!");
    return setCookie;
  }

  // If we got cookies but no redirect, might still be successful
  if (setCookie.length > 0 && (!location || location.includes("/account"))) {
    console.log("Login appears successful (cookies received)");
    return setCookie;
  }

  // Login failed
  throw new Error(`Shopify login failed. Status: ${loginRes.status}, Location: ${location}`);
=======
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
>>>>>>> 7dad952ce2da3a385e4ba412e0c18bf0640d9732
}

app.listen(3000, () => {
  console.log("Auth server running on port 3000");
});
