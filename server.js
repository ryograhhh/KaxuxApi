const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { uploadToImgur } = require("imgur-link");
const app = express();
const port = process.env.PORT || 8080;

const axios = require('axios');
const qs = require('qs');

// Cloudflare Turnstile Configuration
const TURNSTILE_SECRET_KEY = "0x4AAAAAAB8l08bBbzY0aG9jWJEFaxUXA-k";

// Brevo Email Configuration
const BREVO_API_KEY = "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";
const FROM_NAME = "KazuX";
const FROM_EMAIL = "marlonjubiar123@gmail.com";
const REPLY_TO = "marlonjubiar123@gmail.com";

// OTP Storage (in-memory for now, moves to DB for production)
const otpStore = new Map();
const COOLDOWN_MS = 60 * 1000; // 1 minute cooldown
const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes expiry

// Configure Multer for temporary file storage
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!file.mimetype.startsWith('image/')) {
    return cb(new Error('Only image files are allowed!'), false);
  }
  cb(null, true);
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024
  }
});

// MongoDB Connection
const uri = "mongodb+srv://biarpogihehe:XaneKath1@cluster0.beucph6.mongodb.net/facebook-token-api?retryWrites=true&w=majority&appName=Cluster0";
const clientOptions = { 
  serverApi: { 
    version: '1', 
    strict: false,
    deprecationErrors: true 
  } 
};

mongoose.connect(uri, clientOptions)
  .then(() => {
    console.log("Successfully connected to MongoDB!");
    createAdminAccount();
  })
  .catch(err => console.error("MongoDB connection error:", err));

// User Schema (Updated with email and verification)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  emailVerified: { type: Boolean, default: false },
  password: { type: String, required: true },
  gender: { type: String, enum: ['male', 'female', 'other'], required: true },
  birthday: { type: Date, required: true },
  profilePicture: { type: String, default: null },
  verifiedBadge: { type: String, default: null },
  apiKey: { type: String, required: true, unique: true },
  requestCount: { type: Number, default: 0 },
  lastRequest: { type: Date },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  isAdmin: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  banReason: { type: String, default: null },
  bannedAt: { type: Date, default: null },
  bannedBy: { type: String, default: null }
});

const User = mongoose.model('User', userSchema);

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  lastSent: { type: Date, default: Date.now },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTP = mongoose.model('OTP', otpSchema);

// API Request Log Schema
const requestLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: { type: String },
  apiKey: { type: String, required: true },
  endpoint: { type: String },
  method: { type: String },
  success: { type: Boolean },
  timestamp: { type: Date, default: Date.now },
  ipAddress: { type: String },
  errorMessage: { type: String }
});

const RequestLog = mongoose.model('RequestLog', requestLogSchema);

// Session Schema
const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

const Session = mongoose.model('Session', sessionSchema);

// Announcement Schema
const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdByUsername: { type: String, required: true },
  createdByProfilePicture: { type: String, default: null },
  createdByVerifiedBadge: { type: String, default: null },
  createdByIsAdmin: { type: Boolean, default: false },
  createdByTag: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: null }
});

const Announcement = mongoose.model('Announcement', announcementSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Generate API Key
function generateApiKey() {
  return 'fbk_' + crypto.randomBytes(32).toString('hex');
}

// Generate Session Token
function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

// Generate OTP
function generateOTP() {
  return String(crypto.randomInt(100000, 1000000));
}

// Helper function to upload buffer to Imgur
async function uploadBufferToImgur(buffer, filename) {
  try {
    const tempPath = path.join(__dirname, 'temp_' + filename);
    fs.writeFileSync(tempPath, buffer);
    
    const imgurUrl = await uploadToImgur(tempPath);
    
    fs.unlinkSync(tempPath);
    
    return imgurUrl;
  } catch (error) {
    const tempPath = path.join(__dirname, 'temp_' + filename);
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
    throw error;
  }
}

// Cloudflare Turnstile Verification
async function verifyTurnstile(token, ip) {
  try {
    const form = new URLSearchParams();
    form.append('secret', TURNSTILE_SECRET_KEY);
    form.append('response', token);
    if (ip) form.append('remoteip', ip);

    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form
    });

    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}

// Send Email via Brevo
async function sendEmail(to, subject, html, traceId) {
  const text = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  const payload = {
    sender: { email: FROM_EMAIL, name: FROM_NAME },
    replyTo: { email: REPLY_TO, name: FROM_NAME },
    to: [{ email: to }],
    subject,
    htmlContent: html,
    textContent: text,
    tags: ["otp", `rid-${traceId.slice(0, 10)}`]
  };

  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': BREVO_API_KEY,
        'accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.message || 'Email send failed');
    }

    return {
      messageId: data.messageId || data.messageIdV2 || null,
      status: response.status
    };
  } catch (error) {
    console.error('Email send error:', error);
    throw error;
  }
}

// Create Admin Account
async function createAdminAccount() {
  try {
    const adminExists = await User.findOne({ username: 'Biar' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('XaneKath1', 10);
      await User.create({
        username: 'Biar',
        email: 'admin@kazux.com',
        emailVerified: true,
        password: hashedPassword,
        gender: 'male',
        birthday: new Date('2008-05-02'),
        profilePicture: 'https://i.imgur.com/TKCQWAV.jpeg',
        verifiedBadge: 'https://i.imgur.com/ap56zib.jpeg',
        apiKey: generateApiKey(),
        isAdmin: true
      });
      console.log('✅ Admin account created - Username: Biar, Password: XaneKath1');
    } else {
      if (!adminExists.profilePicture) {
        adminExists.profilePicture = 'https://i.imgur.com/TKCQWAV.jpeg';
      }
      if (!adminExists.verifiedBadge && adminExists.isAdmin) {
        adminExists.verifiedBadge = 'https://i.imgur.com/ap56zib.jpeg';
      }
      if (!adminExists.email) {
        adminExists.email = 'admin@kazux.com';
        adminExists.emailVerified = true;
      }
      await adminExists.save();
      console.log('✅ Admin account already exists');
    }
  } catch (error) {
    console.error('Error creating admin account:', error);
  }
}

// API Key Validation Middleware
async function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.apikey;
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: "API key is required. Use header 'X-API-Key' or query parameter 'apikey'"
    });
  }

  try {
    const user = await User.findOne({ apiKey, isActive: true });
    
    if (!user) {
      await RequestLog.create({
        apiKey: apiKey,
        endpoint: req.path,
        method: req.method,
        success: false,
        ipAddress: req.ip || req.connection.remoteAddress,
        errorMessage: "Invalid or inactive API key"
      });
      
      return res.status(403).json({
        success: false,
        error: "Invalid or inactive API key"
      });
    }

    if (user.isBanned) {
      await RequestLog.create({
        userId: user._id,
        username: user.username,
        apiKey: apiKey,
        endpoint: req.path,
        method: req.method,
        success: false,
        ipAddress: req.ip || req.connection.remoteAddress,
        errorMessage: "User is banned: " + user.banReason
      });
      
      return res.status(403).json({
        success: false,
        error: "Your account has been banned",
        reason: user.banReason,
        bannedAt: user.bannedAt,
        bannedBy: user.bannedBy
      });
    }

    user.requestCount += 1;
    user.lastRequest = new Date();
    await user.save();

    await RequestLog.create({
      userId: user._id,
      username: user.username,
      apiKey: apiKey,
      endpoint: req.path,
      method: req.method,
      success: true,
      ipAddress: req.ip || req.connection.remoteAddress
    });

    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Error validating API key"
    });
  }
}

// Session Authentication Middleware
async function authenticateSession(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '') || req.query.token;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Authentication token is required"
    });
  }

  try {
    const session = await Session.findOne({ 
      token,
      expiresAt: { $gt: new Date() }
    }).populate('userId');
    
    if (!session) {
      return res.status(401).json({
        success: false,
        error: "Invalid or expired session"
      });
    }

    if (session.userId.isBanned) {
      return res.status(403).json({
        success: false,
        error: "Your account has been banned",
        reason: session.userId.banReason,
        bannedAt: session.userId.bannedAt,
        bannedBy: session.userId.bannedBy
      });
    }

    req.user = session.userId;
    req.session = session;
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Error validating session"
    });
  }
}

// Admin Authentication Middleware
async function authenticateAdmin(req, res, next) {
  await authenticateSession(req, res, async () => {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        error: "Admin access required"
      });
    }
    next();
  });
}

// APP IDS
const APP_IDS = {
  "EAAAAU": "350685531728",
  "EAAD": "256002347743983",
  "EAAAAAY": "6628568379",
  "EAADY": "237759909591655",
  "EAAB": "121876164619130",
  "EAAG": "436761779744620",
  "EAAC4": "202805033077166",
  "EAAC2": "200424423651082",
  "EAACW": "165907476854626",
  "EAACn": "184182168294603",
};

async function get(cookie) {
  const uid = cookie.match(/c_user=([^;]+)/)?.[1];
  
  if (!uid) {
    return {
      success: false,
      error: "The cookie you provided doesn't seem to be valid"
    };
  }
  
  try {
    const resp = await axios.get("https://www.facebook.com/ajax/dtsg/?__a", {
      headers: { cookie }
    });
    
    const raw = typeof resp.data === 'string' ? resp.data.replace(/^\s*for\s*\(\s*;;\s*\)\s*;?/, '') : resp.data;
    const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;
    const token = obj?.payload?.token;
    
    if (!token) {
      return {
        success: false,
        error: "Failed to login your account"
      };
    }
    
    const results = await Promise.all(
      Object.entries(APP_IDS).map(async ([key, app_id]) => {
        try {
          const r = await axios.request({
            method: 'POST',
            url: "https://www.facebook.com/api/graphql/",
            headers: { cookie },
            data: qs.stringify({
              'av': uid,
              '__user': uid,
              'fb_dtsg': token,
              'fb_api_caller_class': 'RelayModern',
              'fb_api_req_friendly_name': 'useCometConsentPromptEndOfFlowBatchedMutation',
              'variables': `{"input":{"client_mutation_id":"4","actor_id":${uid},"config_enum":"GDP_READ","device_id":null,"experience_id":"","extra_params_json":"{\\"app_id\\":\\"${app_id}\\",\\"display\\":\\"\\\\\\"popup\\\\\\"\\",\\"kid_directed_site\\":\\"false\\",\\"logger_id\\":\\"\\\\\\"\\\\\\"\\",\\"next\\":\\"\\\\\\"read\\\\\\"\\",\\"redirect_uri\\":\\"\\\\\\"https:\\\\/\\\\/www.facebook.com\\\\/connect\\\\/login_success.html\\\\\\"\\",\\"response_type\\":\\"\\\\\\"token\\\\\\"\\",\\"return_scopes\\":\\"false\\",\\"scope\\":\\"[\\\\\\"email\\\\\\",\\\\\\"public_profile\\\\\\"]\\",\\"sso_key\\":\\"\\\\\\"com\\\\\\"\\",\\"steps\\":\\"{\\\\\\"read\\\\\\":[\\\\\\"email\\\\\\",\\\\\\"public_profile\\\\\\"]}\\",\\"tp\\":\\"\\\\\\"unspecified\\\\\\"\\",\\"cui_gk\\":\\"\\\\\\"[PASS]:\\\\\\"\\",\\"is_limited_login_shim\\":\\"false\\"}","flow_name":"GDP","flow_step_type":"STANDALONE","outcome":"APPROVED","source":"gdp_delegated","surface":"FACEBOOK_COMET"}}`,
              'server_timestamps': 'true',
              'doc_id': '6494107973937368'
            })
          });
          
          const uri = r.data.data.run_post_flow_action.uri;
          
          if (uri) {
            const access = new URL(decodeURIComponent(new URL(uri).searchParams.get('close_uri'))).hash.replace(/^#/, '').split('&').find(p => p.startsWith('access_token='))?.split('=')[1];
            return [key, access || null];
          }
          
          return [key, null];
        } catch {
          return [key, null];
        }
      })
    );
    
    return {
      success: true,
      tokens: Object.fromEntries(results)
    };
  } catch {
    return {
      success: false,
      error: "Failed to login your account"
    };
  }
}

// OTP REQUEST ENDPOINT
app.post('/api/otp/request', async (req, res) => {
  try {
    const { email, turnstileToken } = req.body;
    
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: "Invalid email address"
      });
    }

    // Verify Turnstile
    if (!turnstileToken) {
      return res.status(400).json({
        success: false,
        error: "Captcha verification required"
      });
    }

    const ip = req.headers['cf-connecting-ip'] || req.ip;
    const turnstileValid = await verifyTurnstile(turnstileToken, ip);
    
    if (!turnstileValid) {
      return res.status(403).json({
        success: false,
        error: "Captcha verification failed"
      });
    }

    // Check cooldown
    const existing = await OTP.findOne({ email: email.toLowerCase(), verified: false }).sort({ createdAt: -1 });
    if (existing && Date.now() - existing.lastSent.getTime() < COOLDOWN_MS) {
      const wait = Math.ceil((COOLDOWN_MS - (Date.now() - existing.lastSent.getTime())) / 1000);
      return res.status(429).json({
        success: false,
        error: `Please wait ${wait} seconds before requesting again`
      });
    }

    // Generate and store OTP
    const code = generateOTP();
    const traceId = crypto.randomUUID();
    
    await OTP.create({
      email: email.toLowerCase(),
      code,
      expiresAt: new Date(Date.now() + OTP_EXPIRY_MS),
      lastSent: new Date()
    });

    // Send email
    const html = `
      <div style="font-family: Inter, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: #18181b; color: white; padding: 30px; border-radius: 12px; text-align: center;">
          <h1 style="margin: 0 0 10px 0; font-size: 24px;">KazuX Verification</h1>
          <p style="margin: 0; opacity: 0.8; font-size: 14px;">Your verification code</p>
        </div>
        <div style="background: #fafafa; padding: 40px; border-radius: 12px; margin-top: 20px; text-align: center;">
          <p style="font-size: 16px; color: #52525b; margin: 0 0 20px 0;">Enter this code to verify your email:</p>
          <div style="background: white; border: 2px solid #e4e4e7; border-radius: 12px; padding: 20px; display: inline-block;">
            <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; margin: 0; color: #18181b;">${code}</p>
          </div>
          <p style="font-size: 14px; color: #71717a; margin: 20px 0 0 0;">This code expires in 5 minutes</p>
        </div>
        <div style="text-align: center; margin-top: 20px;">
          <p style="font-size: 12px; color: #a1a1aa;">If you didn't request this code, please ignore this email.</p>
        </div>
      </div>
    `;

    await sendEmail(email, 'Your KazuX Verification Code', html, traceId);

    res.json({
      success: true,
      message: "Verification code sent to your email"
    });
  } catch (error) {
    console.error('OTP request error:', error);
    res.status(500).json({
      success: false,
      error: "Failed to send verification code"
    });
  }
});

// OTP VERIFY ENDPOINT
app.post('/api/otp/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: "Email and code are required"
      });
    }

    if (!/^\d{6}$/.test(String(code))) {
      return res.status(400).json({
        success: false,
        error: "Invalid code format"
      });
    }

    const otpEntry = await OTP.findOne({
      email: email.toLowerCase(),
      verified: false,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: -1 });

    if (!otpEntry) {
      return res.status(400).json({
        success: false,
        error: "Code expired or not found"
      });
    }

    if (otpEntry.attempts >= 5) {
      await OTP.deleteOne({ _id: otpEntry._id });
      return res.status(429).json({
        success: false,
        error: "Too many attempts. Please request a new code"
      });
    }

    otpEntry.attempts += 1;
    await otpEntry.save();

    if (otpEntry.code !== String(code)) {
      return res.status(400).json({
        success: false,
        error: "Invalid code"
      });
    }

    otpEntry.verified = true;
    await otpEntry.save();

    res.json({
      success: true,
      verified: true,
      message: "Email verified successfully"
    });
  } catch (error) {
    console.error('OTP verify error:', error);
    res.status(500).json({
      success: false,
      error: "Verification failed"
    });
  }
});

// AUTH ROUTES
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, gender, birthday, turnstileToken, otpCode } = req.body;
    
    if (!username || !email || !password || !gender || !birthday) {
      return res.status(400).json({
        success: false,
        error: "All fields are required"
      });
    }

    // Verify Turnstile
    if (!turnstileToken) {
      return res.status(400).json({
        success: false,
        error: "Captcha verification required"
      });
    }

    const ip = req.headers['cf-connecting-ip'] || req.ip;
    const turnstileValid = await verifyTurnstile(turnstileToken, ip);
    
    if (!turnstileValid) {
      return res.status(403).json({
        success: false,
        error: "Captcha verification failed"
      });
    }

    // Verify OTP
    if (!otpCode) {
      return res.status(400).json({
        success: false,
        error: "Email verification code required"
      });
    }

    const otpEntry = await OTP.findOne({
      email: email.toLowerCase(),
      code: otpCode,
      verified: true,
      expiresAt: { $gt: new Date() }
    });

    if (!otpEntry) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired verification code"
      });
    }

    if (!['male', 'female', 'other'].includes(gender.toLowerCase())) {
      return res.status(400).json({
        success: false,
        error: "Gender must be 'male', 'female', or 'other'"
      });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email: email.toLowerCase() }] });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: existingUser.username === username ? "Username already exists" : "Email already registered"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const apiKey = generateApiKey();

    const user = await User.create({
      username,
      email: email.toLowerCase(),
      emailVerified: true,
      password: hashedPassword,
      gender: gender.toLowerCase(),
      birthday: new Date(birthday),
      apiKey
    });

    await OTP.deleteMany({ email: email.toLowerCase() });

    await Notification.create({
      userId: user._id,
      title: "Welcome to KazuX API! 🎉",
      message: `Welcome ${username}! Your account has been created successfully. Your API key is ready to use.`,
      type: "success"
    });

    res.json({
      success: true,
      message: "Account created successfully",
      data: {
        username: user.username,
        email: user.email,
        gender: user.gender,
        birthday: user.birthday,
        apiKey: user.apiKey,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to create account: " + error.message
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, turnstileToken } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username and password are required"
      });
    }

    // Verify Turnstile
    if (!turnstileToken) {
      return res.status(400).json({
        success: false,
        error: "Captcha verification required"
      });
    }

    const ip = req.headers['cf-connecting-ip'] || req.ip;
    const turnstileValid = await verifyTurnstile(turnstileToken, ip);
    
    if (!turnstileValid) {
      return res.status(403).json({
        success: false,
        error: "Captcha verification failed"
      });
    }

    const user = await User.findOne({ username, isActive: true });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Invalid username or password"
      });
    }

    if (user.isBanned) {
      return res.status(403).json({
        success: false,
        error: "Your account has been banned",
        reason: user.banReason,
        bannedAt: user.bannedAt,
        bannedBy: user.bannedBy
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: "Invalid username or password"
      });
    }

    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    await Session.create({
      userId: user._id,
      token,
      expiresAt
    });

    res.json({
      success: true,
      message: "Login successful",
      data: {
        token,
        expiresAt,
        user: {
          username: user.username,
          email: user.email,
          gender: user.gender,
          birthday: user.birthday,
          profilePicture: user.profilePicture,
          verifiedBadge: user.verifiedBadge,
          apiKey: user.apiKey,
          isAdmin: user.isAdmin,
          createdAt: user.createdAt
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Login failed: " + error.message
    });
  }
});

app.post('/api/auth/logout', authenticateSession, async (req, res) => {
  try {
    await Session.deleteOne({ _id: req.session._id });
    
    res.json({
      success: true,
      message: "Logged out successfully"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Logout failed"
    });
  }
});

app.get('/api/auth/me', authenticateSession, async (req, res) => {
  try {
    const unreadNotifications = await Notification.countDocuments({
      userId: req.user._id,
      isRead: false
    });

    res.json({
      success: true,
      data: {
        username: req.user.username,
        email: req.user.email,
        gender: req.user.gender,
        birthday: req.user.birthday,
        profilePicture: req.user.profilePicture,
        verifiedBadge: req.user.verifiedBadge,
        apiKey: req.user.apiKey,
        requestCount: req.user.requestCount,
        lastRequest: req.user.lastRequest,
        createdAt: req.user.createdAt,
        isAdmin: req.user.isAdmin,
        unreadNotifications
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch user info"
    });
  }
});

// PROFILE ROUTES
app.get('/api/profile', authenticateSession, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        username: req.user.username,
        email: req.user.email,
        gender: req.user.gender,
        birthday: req.user.birthday,
        profilePicture: req.user.profilePicture,
        verifiedBadge: req.user.verifiedBadge,
        apiKey: req.user.apiKey,
        requestCount: req.user.requestCount,
        lastRequest: req.user.lastRequest,
        createdAt: req.user.createdAt,
        isAdmin: req.user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch profile"
    });
  }
});

// Profile picture upload disabled for regular users
app.post('/api/profile/upload-picture', authenticateSession, async (req, res) => {
  return res.status(403).json({
    success: false,
    error: "Profile picture upload is currently disabled for regular users"
  });
});

// Upload verified badge (Admin only)
app.post('/api/profile/upload-verified-badge', authenticateAdmin, upload.single('verifiedBadge'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No file uploaded"
      });
    }

    const imgurUrl = await uploadBufferToImgur(req.file.buffer, req.file.originalname);

    req.user.verifiedBadge = imgurUrl;
    await req.user.save();

    res.json({
      success: true,
      message: "Verified badge uploaded successfully to Imgur",
      data: {
        verifiedBadge: imgurUrl
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to upload verified badge: " + error.message
    });
  }
});

app.delete('/api/profile/delete-picture', authenticateSession, async (req, res) => {
  try {
    if (!req.user.profilePicture) {
      return res.status(400).json({
        success: false,
        error: "No profile picture to delete"
      });
    }

    req.user.profilePicture = null;
    await req.user.save();

    res.json({
      success: true,
      message: "Profile picture deleted successfully"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to delete profile picture"
    });
  }
});

app.patch('/api/profile/update', authenticateSession, async (req, res) => {
  try {
    const { gender, birthday } = req.body;
    
    if (gender && !['male', 'female', 'other'].includes(gender.toLowerCase())) {
      return res.status(400).json({
        success: false,
        error: "Gender must be 'male', 'female', or 'other'"
      });
    }

    if (gender) req.user.gender = gender.toLowerCase();
    if (birthday) req.user.birthday = new Date(birthday);
    
    await req.user.save();

    res.json({
      success: true,
      message: "Profile updated successfully",
      data: {
        username: req.user.username,
        email: req.user.email,
        gender: req.user.gender,
        birthday: req.user.birthday,
        profilePicture: req.user.profilePicture,
        verifiedBadge: req.user.verifiedBadge
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to update profile"
    });
  }
});

app.patch('/api/profile/change-password', authenticateSession, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Current password and new password are required"
      });
    }

    const isValidPassword = await bcrypt.compare(currentPassword, req.user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: "Current password is incorrect"
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    req.user.password = hashedPassword;
    await req.user.save();

    res.json({
      success: true,
      message: "Password changed successfully"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to change password"
    });
  }
});

app.post('/api/profile/regenerate-apikey', authenticateSession, async (req, res) => {
  try {
    const newApiKey = generateApiKey();
    req.user.apiKey = newApiKey;
    await req.user.save();

    res.json({
      success: true,
      message: "API key regenerated successfully",
      data: {
        apiKey: newApiKey
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to regenerate API key"
    });
  }
});

// NOTIFICATION ROUTES
app.get('/api/notifications', authenticateSession, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);

    const unreadCount = await Notification.countDocuments({
      userId: req.user._id,
      isRead: false
    });

    res.json({
      success: true,
      data: {
        notifications,
        unreadCount
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch notifications"
    });
  }
});

app.patch('/api/notifications/:notificationId/read', authenticateSession, async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.notificationId,
      userId: req.user._id
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        error: "Notification not found"
      });
    }

    notification.isRead = true;
    await notification.save();

    res.json({
      success: true,
      message: "Notification marked as read"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to update notification"
    });
  }
});

app.patch('/api/notifications/read-all', authenticateSession, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user._id, isRead: false },
      { isRead: true }
    );

    res.json({
      success: true,
      message: "All notifications marked as read"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to update notifications"
    });
  }
});

// ANNOUNCEMENT ROUTES
app.get('/api/announcements', async (req, res) => {
  try {
    const announcements = await Announcement.find({
      isActive: true,
      $or: [
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(10);

    res.json({
      success: true,
      data: announcements
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch announcements"
    });
  }
});

// USER STATS ROUTES
app.get('/api/stats', authenticateSession, async (req, res) => {
  try {
    const logs = await RequestLog.find({ userId: req.user._id })
      .sort({ timestamp: -1 })
      .limit(50);

    const successCount = await RequestLog.countDocuments({ 
      userId: req.user._id, 
      success: true 
    });
    
    const failureCount = await RequestLog.countDocuments({ 
      userId: req.user._id, 
      success: false 
    });

    res.json({
      success: true,
      data: {
        user: {
          username: req.user.username,
          email: req.user.email,
          gender: req.user.gender,
          birthday: req.user.birthday,
          profilePicture: req.user.profilePicture,
          verifiedBadge: req.user.verifiedBadge,
          apiKey: req.user.apiKey,
          createdAt: req.user.createdAt
        },
        stats: {
          totalRequests: req.user.requestCount,
          successfulRequests: successCount,
          failedRequests: failureCount,
          lastRequest: req.user.lastRequest
        },
        recentLogs: logs
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch stats"
    });
  }
});

// ADMIN ROUTES
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch users"
    });
  }
});

app.get('/api/admin/logs', authenticateAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const logs = await RequestLog.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .populate('userId', 'username');
    
    res.json({
      success: true,
      count: logs.length,
      data: logs
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch logs"
    });
  }
});

app.get('/api/admin/statistics', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const bannedUsers = await User.countDocuments({ isBanned: true });
    const totalRequests = await RequestLog.countDocuments();
    const successfulRequests = await RequestLog.countDocuments({ success: true });
    const failedRequests = await RequestLog.countDocuments({ success: false });
    
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const requestsByDay = await RequestLog.aggregate([
      { $match: { timestamp: { $gte: sevenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const topUsers = await User.find()
      .select('username requestCount lastRequest profilePicture verifiedBadge')
      .sort({ requestCount: -1 })
      .limit(10);

    res.json({
      success: true,
      data: {
        overview: {
          totalUsers,
          activeUsers,
          bannedUsers,
          totalRequests,
          successfulRequests,
          failedRequests,
          successRate: totalRequests > 0 ? ((successfulRequests / totalRequests) * 100).toFixed(2) + '%' : '0%'
        },
        requestsByDay,
        topUsers
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch statistics"
    });
  }
});

app.patch('/api/admin/users/:userId/toggle-active', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    user.isActive = !user.isActive;
    await user.save();

    await Notification.create({
      userId: user._id,
      title: user.isActive ? "Account Activated ✅" : "Account Deactivated ⚠️",
      message: user.isActive 
        ? "Your account has been activated by an administrator." 
        : "Your account has been deactivated by an administrator.",
      type: user.isActive ? "success" : "warning"
    });

    res.json({
      success: true,
      message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
      data: {
        username: user.username,
        isActive: user.isActive
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to update user status"
    });
  }
});

app.post('/api/admin/users/:userId/ban', authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    if (!reason) {
      return res.status(400).json({
        success: false,
        error: "Ban reason is required"
      });
    }

    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    if (user.isAdmin) {
      return res.status(403).json({
        success: false,
        error: "Cannot ban admin users"
      });
    }

    user.isBanned = true;
    user.banReason = reason;
    user.bannedAt = new Date();
    user.bannedBy = req.user.username;
    await user.save();

    await Notification.create({
      userId: user._id,
      title: "Account Banned 🚫",
      message: `Your account has been banned. Reason: ${reason}`,
      type: "error"
    });

    res.json({
      success: true,
      message: "User banned successfully",
      data: {
        username: user.username,
        isBanned: true,
        banReason: reason,
        bannedAt: user.bannedAt,
        bannedBy: user.bannedBy
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to ban user"
    });
  }
});

app.post('/api/admin/users/:userId/unban', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    user.isBanned = false;
    user.banReason = null;
    user.bannedAt = null;
    user.bannedBy = null;
    await user.save();

    await Notification.create({
      userId: user._id,
      title: "Account Unbanned ✅",
      message: "Your account has been unbanned. You can now use the API again.",
      type: "success"
    });

    res.json({
      success: true,
      message: "User unbanned successfully",
      data: {
        username: user.username,
        isBanned: false
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to unban user"
    });
  }
});

app.delete('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found"
      });
    }

    if (user.isAdmin) {
      return res.status(403).json({
        success: false,
        error: "Cannot delete admin users"
      });
    }

    await User.findByIdAndDelete(req.params.userId);
    await RequestLog.deleteMany({ userId: user._id });
    await Session.deleteMany({ userId: user._id });
    await Notification.deleteMany({ userId: user._id });

    res.json({
      success: true,
      message: "User deleted successfully"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to delete user"
    });
  }
});

app.post('/api/admin/announcements', authenticateAdmin, async (req, res) => {
  try {
    const { title, message, type, expiresAt } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({
        success: false,
        error: "Title and message are required"
      });
    }

    const adminTag = `@${req.user.username}`;

    const announcement = await Announcement.create({
      title,
      message,
      type: type || 'info',
      expiresAt: expiresAt ? new Date(expiresAt) : null,
      createdBy: req.user._id,
      createdByUsername: req.user.username,
      createdByProfilePicture: req.user.profilePicture,
      createdByVerifiedBadge: req.user.verifiedBadge,
      createdByIsAdmin: req.user.isAdmin,
      createdByTag: adminTag
    });

    const users = await User.find({ isActive: true });
    const notifications = users.map(user => ({
      userId: user._id,
      title: `📢 ${title}`,
      message: message,
      type: type || 'info'
    }));
    
    await Notification.insertMany(notifications);

    res.json({
      success: true,
      message: "Announcement created successfully",
      data: announcement
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to create announcement"
    });
  }
});

app.get('/api/admin/announcements', authenticateAdmin, async (req, res) => {
  try {
    const announcements = await Announcement.find()
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      count: announcements.length,
      data: announcements
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch announcements"
    });
  }
});

app.delete('/api/admin/announcements/:announcementId', authenticateAdmin, async (req, res) => {
  try {
    const announcement = await Announcement.findByIdAndDelete(req.params.announcementId);
    
    if (!announcement) {
      return res.status(404).json({
        success: false,
        error: "Announcement not found"
      });
    }

    res.json({
      success: true,
      message: "Announcement deleted successfully"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to delete announcement"
    });
  }
});

app.patch('/api/admin/announcements/:announcementId/toggle', authenticateAdmin, async (req, res) => {
  try {
    const announcement = await Announcement.findById(req.params.announcementId);
    
    if (!announcement) {
      return res.status(404).json({
        success: false,
        error: "Announcement not found"
      });
    }

    announcement.isActive = !announcement.isActive;
    await announcement.save();

    res.json({
      success: true,
      message: `Announcement ${announcement.isActive ? 'activated' : 'deactivated'} successfully`,
      data: announcement
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to update announcement"
    });
  }
});

// TOKEN ENDPOINT
app.get('/token/:cookie', validateApiKey, async (req, res) => {
  const cookie = req.params.cookie;
  
  if (!cookie) {
    const lastLog = await RequestLog.findOne({ userId: req.user._id })
      .sort({ timestamp: -1 });
    
    if (lastLog) {
      lastLog.success = false;
      lastLog.errorMessage = "Cookie parameter is required";
      await lastLog.save();
    }
    
    return res.json({
      success: false,
      error: "cookie is required"
    });
  }
  
  try {
    const result = await get(cookie);
    
    const lastLog = await RequestLog.findOne({ userId: req.user._id })
      .sort({ timestamp: -1 });
    
    if (lastLog) {
      lastLog.success = result.success;
      lastLog.errorMessage = result.success ? null : result.error;
      await lastLog.save();
    }
    
    res.json(result);
  } catch (error) {
    const lastLog = await RequestLog.findOne({ userId: req.user._id })
      .sort({ timestamp: -1 });
    
    if (lastLog) {
      lastLog.success = false;
      lastLog.errorMessage = error.message;
      await lastLog.save();
    }
    
    res.json({
      success: false,
      error: "Something went wrong. Please retry"
    });
  }
});

// DOCUMENTATION ENDPOINT
app.get('/api/documentation', (req, res) => {
  res.json({
    success: true,
    documentation: {
      title: "KazuX API - Facebook Token Generator",
      version: "2.0.0",
      description: "Generate Facebook access tokens from cookies with email verification and captcha protection",
      baseUrl: req.protocol + '://' + req.get('host'),
      authentication: {
        method: "API Key",
        description: "All requests require an API key. Sign up on the website to get your API key.",
        how_to_use: [
          "1. Create an account on the website with email verification",
          "2. Complete Cloudflare Turnstile captcha verification",
          "3. Get your API key from your profile",
          "4. Include the API key in your requests using one of these methods:",
          "   - Header: X-API-Key: your_api_key",
          "   - Query parameter: ?apikey=your_api_key"
        ]
      },
      endpoint: {
        path: "/token/:cookie",
        method: "GET",
        description: "Generate Facebook access tokens from your Facebook cookie",
        parameters: {
          cookie: {
            type: "string",
            location: "path",
            required: true,
            description: "Your Facebook cookie string (must contain c_user)"
          }
        },
        headers: {
          "X-API-Key": {
            type: "string",
            required: true,
            description: "Your API key"
          }
        },
        example_request: {
          curl: `curl -X GET "${req.protocol + '://' + req.get('host')}/token/YOUR_FACEBOOK_COOKIE" \\
  -H "X-API-Key: your_api_key"`,
          javascript: `fetch('${req.protocol + '://' + req.get('host')}/token/YOUR_FACEBOOK_COOKIE', {
  headers: {
    'X-API-Key': 'your_api_key'
  }
})
.then(res => res.json())
.then(data => console.log(data));`,
          python: `import requests

url = '${req.protocol + '://' + req.get('host')}/token/YOUR_FACEBOOK_COOKIE'
headers = {'X-API-Key': 'your_api_key'}

response = requests.get(url, headers=headers)
print(response.json())`
        },
        response_success: {
          success: true,
          tokens: {
            EAAAAU: "token_string_or_null",
            EAAD: "token_string_or_null",
            EAAAAAY: "token_string_or_null",
            EAADY: "token_string_or_null",
            EAAB: "token_string_or_null",
            EAAG: "token_string_or_null",
            EAAC4: "token_string_or_null",
            EAAC2: "token_string_or_null",
            EAACW: "token_string_or_null",
            EAACn: "token_string_or_null"
          }
        },
        response_error: {
          success: false,
          error: "Error message description"
        },
        error_codes: {
          "401": "API key is required",
          "403": "Invalid API key, captcha failed, or account banned",
          "400": "Invalid cookie format",
          "500": "Server error"
        }
      },
      token_types: {
        EAAAAU: "App ID: 350685531728",
        EAAD: "App ID: 256002347743983",
        EAAAAAY: "App ID: 6628568379",
        EAADY: "App ID: 237759909591655",
        EAAB: "App ID: 121876164619130",
        EAAG: "App ID: 436761779744620",
        EAAC4: "App ID: 202805033077166",
        EAAC2: "App ID: 200424423651082",
        EAACW: "App ID: 165907476854626",
        EAACn: "App ID: 184182168294603"
      },
      notes: [
        "Email verification required during signup",
        "Cloudflare Turnstile captcha protection enabled",
        "Some tokens may return null if they cannot be generated",
        "Your API key usage is tracked and logged",
        "Respect Facebook's terms of service when using tokens",
        "Tokens are generated in real-time and not stored on our servers",
        "Profile picture upload is disabled for regular users",
        "Admin users can upload verified badges via Imgur",
        "Admin users have verified badges shown in announcements"
      ]
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ success: true, status: 'healthy', timestamp: new Date() });
});

app.listen(port, () => console.log(`✅ Server running on port ${port}`));

module.exports = app;
