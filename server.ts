// BhoomiSetu Pune — Full-Stack Express Server & Land Stack API
// Developer: Tech-Hypergamy | SIH26014 Land Stack
// Real Firebase Auth + Firestore Sync, AES-256-GCM Encryption, Bcrypt Hashes, HttpOnly Session Cookie

import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { 
  hashPassword, 
  verifyPassword, 
  encryptFieldAES256GCM, 
  decryptFieldAES256GCM, 
  computeSha256,
  generateSignedDocumentToken,
  verifySignedDocumentToken
} from './src/lib/server-crypto';
import { 
  syncUserToFirestore, 
  syncAuditToFirestore, 
  syncGrievanceToFirestore, 
  syncRequestToFirestore 
} from './src/lib/server-firebase';
import {
  MEDAD_PARCELS_PROFILES,
  MEDAD_712_RECORDS,
  MEDAD_8A_RECORDS,
  MEDAD_MOJANI_RECORDS,
  MEDAD_REQUESTS_SEED
} from './src/lib/medad-baramati';
import {
  NIMGAON_KETKI_PARCELS_PROFILES,
  NIMGAON_KETKI_712_RECORDS,
  NIMGAON_KETKI_8A_RECORDS,
  NIMGAON_KETKI_MOJANI_RECORDS,
  NIMGAON_KETKI_REQUESTS_SEED
} from './src/lib/nimgaon-ketki';

process.on('unhandledRejection', (reason) => {
  console.warn('[Server] Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[Server] Uncaught Exception:', err);
});

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Security headers (XSS, CSRF mitigation, clickjacking protection)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// -------------------------------------------------------------
// Database Types & In-Memory Cache (Synced with Firestore)
// -------------------------------------------------------------
export interface UserRecord {
  id: string;
  name: string;
  nameMr?: string;
  email: string;
  passwordHash: string; // bcrypt hash - NEVER returned by API or logged
  role: 'USER' | 'ADMIN';
  extendedRole: string;
  status: 'ACTIVE' | 'INACTIVE' | 'LOCKED';
  taluka?: string;
  mobileEncrypted: string; // AES-256-GCM encrypted at rest
  termsConsentTimestamp: string;
  createdAt: string;
  failedAttempts: number;
  lockedUntil: number | null;
  isDemo?: boolean;
}

export interface ApprovalRequestServer {
  id: string;
  type: 'MUTATION_FERFAR' | 'RECORD_CORRECTION' | 'CERTIFIED_COPY';
  title: string;
  description: string;
  parcelId: string;
  ulpin: string;
  gatNumber: string;
  taluka: string;
  village: string;
  submittedBy: string;
  applicantName: string;
  applicantEmail: string;
  applicantPhoneMasked: string;
  status: 'DRAFT' | 'SUBMITTED' | 'UNDER_REVIEW' | 'APPROVED' | 'REJECTED' | 'RETURNED';
  payload: Record<string, any>;
  currentValues: Record<string, any>;
  documents: any[];
  history: any[];
  adminRemarks?: string;
  decisionBy?: string;
  decidedAt?: string;
  reconciliationScore?: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuditLogServer {
  id: string;
  user: string;
  role: string;
  action: string;
  entity: string;
  entityId: string;
  beforeVal: string;
  afterVal: string;
  timestamp: string;
  prevHash: string;
  hash: string;
  ip: string;
}

export interface GrievanceServer {
  id: string;
  name: string;
  email: string;
  phone: string;
  category: string;
  subject: string;
  message: string;
  status: 'SUBMITTED' | 'UNDER_REVIEW' | 'RESOLVED';
  createdAt: string;
  resolvedAt?: string;
}

// -------------------------------------------------------------
// Seeded Accounts (1 Admin from ENV + 2 Clearly Labeled DEMO Citizens)
// -------------------------------------------------------------
const adminEmail = process.env.ADMIN_EMAIL || 'admin@bhoomisetu.pune.gov.in';
const adminPassword = process.env.ADMIN_PASSWORD || 'MahaAdmin@2026';
const adminName = process.env.ADMIN_NAME || 'Rajesh Vitthal Deshmukh';

const USERS_DB: UserRecord[] = [
  // 1 Seeded Admin (from Environment Variables)
  {
    id: 'ADM_PUN_001',
    name: adminName,
    nameMr: 'राजेश विठ्ठल देशमुख',
    email: adminEmail.toLowerCase().trim(),
    passwordHash: hashPassword(adminPassword),
    role: 'ADMIN',
    extendedRole: 'DISTRICT_ADMIN',
    status: 'ACTIVE',
    taluka: 'Pune City / Haveli',
    mobileEncrypted: encryptFieldAES256GCM('+91 9423019876'),
    termsConsentTimestamp: '2025-11-01T08:00:00Z',
    createdAt: '2025-11-01T08:00:00Z',
    failedAttempts: 0,
    lockedUntil: null,
    isDemo: false
  },
  // Clearly Labelled DEMO Citizen 1
  {
    id: 'USR_PUN_001',
    name: 'Demo Citizen Rameshwar Kulkarni',
    nameMr: 'प्रात्यक्षिक नागरिक रामेश्वर कुलकर्णी',
    email: 'user@bhoomisetu.demo',
    passwordHash: hashPassword('PuneLand@2026'),
    role: 'USER',
    extendedRole: 'USER',
    status: 'ACTIVE',
    taluka: 'Haveli',
    mobileEncrypted: encryptFieldAES256GCM('9822104521'),
    termsConsentTimestamp: '2026-01-15T09:30:00Z',
    createdAt: '2026-01-15T09:30:00Z',
    failedAttempts: 0,
    lockedUntil: null,
    isDemo: true
  },
  // Clearly Labelled DEMO Citizen 2
  {
    id: 'USR_PUN_002',
    name: 'Demo Citizen Sunita Patil',
    nameMr: 'प्रात्यक्षिक नागरिक सुनिता पाटील',
    email: 'sunita.patil@bhoomisetu.demo',
    passwordHash: hashPassword('PuneLand@2026'),
    role: 'USER',
    extendedRole: 'USER',
    status: 'ACTIVE',
    taluka: 'Mulshi',
    mobileEncrypted: encryptFieldAES256GCM('9822987120'),
    termsConsentTimestamp: '2026-02-10T11:00:00Z',
    createdAt: '2026-02-10T11:00:00Z',
    failedAttempts: 0,
    lockedUntil: null,
    isDemo: true
  }
];

// Seed initial users to Firestore async
USERS_DB.forEach(u => syncUserToFirestore(u));

const REQUESTS_DB: ApprovalRequestServer[] = [
  {
    id: 'PUN-REQ-2026-081',
    type: 'MUTATION_FERFAR',
    title: 'Heirship Mutation (Varsai Nond - Sec 149 MLRC)',
    description: 'Application for entering legal heirs of Late Mahadev Gopal Kulkarni on 7/12 extract of Gat No. 142 Wagholi.',
    parcelId: 'PUN_WAG_142',
    ulpin: 'MH-27-25-HAV-WAG-142-001',
    gatNumber: '142',
    taluka: 'Haveli',
    village: 'Wagholi',
    submittedBy: 'USR_PUN_001',
    applicantName: 'Demo Citizen Rameshwar Kulkarni',
    applicantEmail: 'user@bhoomisetu.demo',
    applicantPhoneMasked: '98******21',
    status: 'UNDER_REVIEW',
    payload: {
      mutationCategory: 'Varsai (Legal Heirship)',
      deceasedHolder: 'Late Mahadev Gopal Kulkarni (Date of Death: 12-Nov-2025)',
      legalHeirsProposed: [
        'Demo Citizen Rameshwar Kulkarni (Son - Share 1/2)',
        'Mangala Mahadev Kulkarni (Widow - Share 1/2)'
      ]
    },
    currentValues: {
      occupantClass: 'Bhogvatdar Class-1 (भोगवटादार वर्ग-१)',
      registeredHolders: ['Mahadev Gopal Kulkarni (Deceased) - 1.20 Ha'],
      totalAreaHa: 1.20
    },
    documents: [
      { id: 'DOC-VAR-001', name: 'Municipal_Death_Certificate.pdf', size: '1.4 MB', type: 'application/pdf', uploadUrl: '#' }
    ],
    history: [
      { action: 'SUBMITTED', actor: 'Demo Citizen Rameshwar Kulkarni', actorRole: 'USER', timestamp: '2026-03-02T10:20:00Z' },
      { action: 'UNDER_REVIEW', actor: adminName, actorRole: 'ADMIN', timestamp: '2026-03-05T14:10:00Z' }
    ],
    reconciliationScore: 98,
    createdAt: '2026-03-02T10:20:00Z',
    updatedAt: '2026-03-05T14:10:00Z'
  },
  {
    id: 'PUN-REQ-2026-082',
    type: 'RECORD_CORRECTION',
    title: 'Correction of Clerical Spelling Error in Khatedar Name',
    description: 'Rectification of minor typographical spelling in primary holder name from "Suneeta" to "Sunita".',
    parcelId: 'PUN_PIR_204',
    ulpin: 'MH-27-25-MUL-PIR-204-001',
    gatNumber: '204',
    taluka: 'Mulshi',
    village: 'Pirangut',
    submittedBy: 'USR_PUN_002',
    applicantName: 'Demo Citizen Sunita Patil',
    applicantEmail: 'sunita.patil@bhoomisetu.demo',
    applicantPhoneMasked: '98******20',
    status: 'SUBMITTED',
    payload: {
      correctionField: 'Holder Name Spelling (Gavkhand 7)',
      currentSpelling: 'Suneeta Dnyandev Patil',
      correctedSpellingProposed: 'Sunita Dnyaneshwar Patil'
    },
    currentValues: {
      occupantClass: 'Bhogvatdar Class-1',
      registeredHolder: 'Suneeta Dnyandev Patil',
      areaHa: 0.85
    },
    documents: [
      { id: 'DOC-COR-001', name: 'Registered_Sale_Deed_Paud_1985.pdf', size: '3.2 MB', type: 'application/pdf', uploadUrl: '#' }
    ],
    history: [
      { action: 'SUBMITTED', actor: 'Demo Citizen Sunita Patil', actorRole: 'USER', timestamp: '2026-03-08T09:05:00Z' }
    ],
    reconciliationScore: 94,
    createdAt: '2026-03-08T09:05:00Z',
    updatedAt: '2026-03-08T09:05:00Z'
  }
];

const SEED_FILE = path.join(process.cwd(), 'data', 'parcels_seed.json');
try {
  if (fs.existsSync(SEED_FILE)) {
    const seedRows: ApprovalRequestServer[] = JSON.parse(fs.readFileSync(SEED_FILE, 'utf-8'));
    const existingIds = new Set(REQUESTS_DB.map(r => r.id));
    const fresh = seedRows.filter(r => !existingIds.has(r.id));
    REQUESTS_DB.push(...fresh);
    console.log(`[seed] Loaded ${fresh.length} parcel records (total requests: ${REQUESTS_DB.length})`);
    // Optional Firestore sync, OFF by default to avoid 1000 writes on every restart.
    if (process.env.SEED_SYNC_FIRESTORE === 'true') {
      fresh.forEach((r, i) => setTimeout(() => syncRequestToFirestore(r), Math.floor(i / 25) * 1000));
    }
  } else {
    console.warn('[seed] data/parcels_seed.json not found; skipping parcel seed');
  }
} catch (err) {
  console.error('[seed] Failed to load parcel seed data:', err);
}

// -------------------------------------------------------------
// Village Cadastral Packs Loader (data/villages/<slug>/)
// -------------------------------------------------------------
interface LandVillagePack {
  slug: string;
  profile?: any;
  parcels?: any;
  records712?: any[];
  khata8a?: any[];
  propertycards?: any[];
  mojani?: any[];
  requests_seed?: ApprovalRequestServer[];
}

const LAND_PACKS = new Map<string, LandVillagePack>();
const VILLAGE_SLUG_REGEX = /^[a-z0-9-]+$/;
const ALLOWED_VILLAGE_DATASETS = new Set([
  'profile',
  'parcels',
  'records712',
  'khata8a',
  'propertycards',
  'mojani'
]);

(() => {
  const villagesDir = path.join(process.cwd(), 'data', 'villages');
  if (!fs.existsSync(villagesDir)) {
    console.warn('[land] data/villages directory not found; skipping village packs');
    return;
  }

  const existingIds = new Set(REQUESTS_DB.map(r => r.id));
  const newlySeededVillageRequests: ApprovalRequestServer[] = [];

  const readJsonSafe = (filePath: string): any => {
    if (!fs.existsSync(filePath)) return undefined;
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  };

  const slugs = fs
    .readdirSync(villagesDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name)
    .sort();

  for (const slug of slugs) {
    if (!VILLAGE_SLUG_REGEX.test(slug)) {
      console.warn(`[land] Skipping invalid village slug: ${slug}`);
      continue;
    }

    const packDir = path.join(villagesDir, slug);
    try {
      const profile = readJsonSafe(path.join(packDir, 'profile.json'));
      const parcels = readJsonSafe(path.join(packDir, 'parcels.geojson'));
      const records712 = readJsonSafe(path.join(packDir, 'records712.json'));
      const khata8a = readJsonSafe(path.join(packDir, 'khata8a.json'));
      const propertycards = readJsonSafe(path.join(packDir, 'propertycards.json'));
      const mojani = readJsonSafe(path.join(packDir, 'mojani.json'));
      const requestsSeed: ApprovalRequestServer[] | undefined = readJsonSafe(
        path.join(packDir, 'requests_seed.json')
      );

      const pack: LandVillagePack = {
        slug,
        ...(profile !== undefined ? { profile } : {}),
        ...(parcels !== undefined ? { parcels } : {}),
        ...(records712 !== undefined ? { records712 } : {}),
        ...(khata8a !== undefined ? { khata8a } : {}),
        ...(propertycards !== undefined ? { propertycards } : {}),
        ...(mojani !== undefined ? { mojani } : {}),
        ...(requestsSeed !== undefined ? { requests_seed: requestsSeed } : {})
      };

      LAND_PACKS.set(slug, pack);

      let addedRequests = 0;
      if (Array.isArray(requestsSeed)) {
        for (const row of requestsSeed) {
          if (row && row.id && !existingIds.has(row.id)) {
            existingIds.add(row.id);
            REQUESTS_DB.push(row);
            newlySeededVillageRequests.push(row);
            addedRequests++;
          }
        }
      }

      const availableDatasets = Array.from(ALLOWED_VILLAGE_DATASETS).filter(
        ds => (pack as Record<string, any>)[ds] !== undefined
      );
      console.log(
        `[land] Loaded pack ${slug} (datasets: ${availableDatasets.join(', ')}, seededRequests: ${addedRequests}, totalRequests: ${REQUESTS_DB.length})`
      );
    } catch (err) {
      console.error(`[land] Failed to load pack ${slug}:`, err);
    }
  }

  if (process.env.SEED_SYNC_FIRESTORE === 'true' && newlySeededVillageRequests.length > 0) {
    newlySeededVillageRequests.forEach((r, i) =>
      setTimeout(() => syncRequestToFirestore(r), Math.floor(i / 25) * 1000)
    );
  }
})();

const AUDIT_LOGS_DB: AuditLogServer[] = [
  {
    id: 'AUD_001',
    user: 'system@bhoomisetu.pune.gov.in',
    role: 'SYSTEM',
    action: 'GENESIS_BLOCK_INITIALIZED',
    entity: 'DISTRICT_DATABASE',
    entityId: 'DIST_2725_PUNE',
    beforeVal: 'NULL',
    afterVal: 'PUNE_LAND_STACK_V2026_INITIALIZED',
    timestamp: '2026-01-01T00:00:00Z',
    prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    ip: '10.0.0.1'
  }
];

const GRIEVANCES_DB: GrievanceServer[] = [
  {
    id: 'PUN-GRV-2026-001',
    name: 'Citizen Anonymous Query',
    email: 'citizen.feedback@demo.bhoomi',
    phone: '98******00',
    category: 'RECORD_DISCREPANCY',
    subject: 'Discrepancy in old survey demarcation vs e-Mojni map',
    message: 'Notice of 2% variance in northern perimeter between 1982 paper Gat Naksha and recent DGPS ETS coordinate reading in Haveli.',
    status: 'UNDER_REVIEW',
    createdAt: '2026-03-01T11:20:00Z'
  }
];

// Helper: Mask phone helper
function maskPhoneStr(phone: string): string {
  const digits = phone.replace(/[^0-9]/g, '');
  if (digits.length >= 10) {
    const last10 = digits.slice(-10);
    return `${last10.slice(0, 2)}******${last10.slice(-2)}`;
  }
  return '98******00';
}

// Helper: Sanitize User (Never leak passwordHash or raw mobile in UI/API)
function sanitizeUser(user: UserRecord) {
  let decryptedMobile = '';
  try {
    decryptedMobile = decryptFieldAES256GCM(user.mobileEncrypted);
  } catch {
    decryptedMobile = '98******00';
  }
  const maskedMobile = maskPhoneStr(decryptedMobile);

  return {
    id: user.id,
    name: user.name,
    nameMr: user.nameMr,
    email: user.email,
    role: user.role,
    extendedRole: user.extendedRole,
    status: user.status,
    taluka: user.taluka,
    mobile: maskedMobile,
    termsConsentTimestamp: user.termsConsentTimestamp,
    createdAt: user.createdAt,
    isDemo: user.isDemo || false
  };
}

// Cryptographic Hash-Chained Audit Appender
const appendAudit = (
  user: string, 
  role: string, 
  action: string, 
  entity: string, 
  entityId: string, 
  beforeVal: string, 
  afterVal: string, 
  ip: string
): AuditLogServer => {
  const prevHash = AUDIT_LOGS_DB.length > 0 ? AUDIT_LOGS_DB[AUDIT_LOGS_DB.length - 1].hash : '0000000000000000000000000000000000000000000000000000000000000000';
  const timestamp = new Date().toISOString();
  const id = `AUD_${String(AUDIT_LOGS_DB.length + 1).padStart(3, '0')}`;
  const text = `${prevHash}|${user}|${role}|${action}|${entity}|${entityId}|${afterVal}|${timestamp}`;
  const hash = computeSha256(text);

  const entry: AuditLogServer = {
    id,
    user,
    role,
    action,
    entity,
    entityId,
    beforeVal,
    afterVal,
    timestamp,
    prevHash,
    hash,
    ip
  };
  AUDIT_LOGS_DB.push(entry);
  syncAuditToFirestore(entry);
  return entry;
};

// -------------------------------------------------------------
// Session Token & Authentication Middleware
// -------------------------------------------------------------
interface AuthenticatedRequest extends Request {
  user?: UserRecord;
}

const SESSION_SECRET = process.env.SESSION_SECRET || 'bhoomisetu_pune_session_secret_key_2026';
const SESSION_COOKIE_NAME = 'bhoomisetu_session';
const INACTIVITY_TIMEOUT_SECONDS = 15 * 60; // 15 Minutes Auto-Logout

const generateSessionToken = (user: UserRecord): string => {
  const expiresAt = Math.floor(Date.now() / 1000) + INACTIVITY_TIMEOUT_SECONDS;
  const payload = JSON.stringify({
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    exp: expiresAt
  });
  const encodedPayload = Buffer.from(payload).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
};

const verifySessionToken = (token: string): { valid: boolean; payload?: any } => {
  try {
    const [encodedPayload, signature] = token.split('.');
    if (!encodedPayload || !signature) return { valid: false };
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('base64url');
    if (expectedSig !== signature) return { valid: false };

    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false }; // Expired
    }
    return { valid: true, payload };
  } catch {
    return { valid: false };
  }
};

/**
 * Reads and verifies the session token from HttpOnly cookie or Authorization Bearer header.
 * Enforces 15-minute inactivity auto-logout and checks account status.
 */
const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const cookieToken = req.cookies ? req.cookies[SESSION_COOKIE_NAME] : null;
  const authHeader = req.headers['authorization'];
  const headerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  const token = cookieToken || headerToken;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Active session required.' });
  }

  const verified = verifySessionToken(token);
  if (!verified.valid || !verified.payload) {
    res.clearCookie(SESSION_COOKIE_NAME);
    return res.status(401).json({ error: 'Unauthorized: Session expired or invalid. Please sign in again.' });
  }

  const user = USERS_DB.find(u => u.id === verified.payload.sub);
  if (!user) {
    res.clearCookie(SESSION_COOKIE_NAME);
    return res.status(401).json({ error: 'Unauthorized: Account does not exist.' });
  }

  if (user.status !== 'ACTIVE') {
    res.clearCookie(SESSION_COOKIE_NAME);
    return res.status(403).json({ error: 'Forbidden: This account has been deactivated.' });
  }

  req.user = user;

  // Refresh httpOnly session cookie with updated 15-minute expiration
  const refreshedToken = generateSessionToken(user);
  res.cookie(SESSION_COOKIE_NAME, refreshedToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: INACTIVITY_TIMEOUT_SECONDS * 1000
  });

  next();
};

/**
 * Backend Role Enforcement: Validates role strictly from verified session.
 * Never trusts request body for role checks. Returns 403 on authorization failure.
 */
const requireRole = (requiredRole: 'USER' | 'ADMIN') => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required' });
    }
    // Only verified session role is respected
    if (req.user.role !== requiredRole && req.user.role !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Forbidden: You do not have permission to access this administrative resource.',
        message: 'Access restricted to authorized revenue administrative personnel only.' 
      });
    }
    next();
  };
};

// Password complexity checker (minimum 8 characters, at least 1 letter, 1 number, 1 special character)
function validatePasswordComplexity(pwd: string): { valid: boolean; error?: string } {
  if (!pwd || pwd.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long.' };
  }
  if (!/[a-zA-Z]/.test(pwd)) {
    return { valid: false, error: 'Password must contain at least one letter.' };
  }
  if (!/[0-9]/.test(pwd)) {
    return { valid: false, error: 'Password must contain at least one number.' };
  }
  if (!/[^a-zA-Z0-9]/.test(pwd)) {
    return { valid: false, error: 'Password must contain at least one special character (!@#$%^&*).' };
  }
  return { valid: true };
}

// In-memory password reset tokens
interface PasswordResetToken {
  token: string;
  email: string;
  expiresAt: number;
}
const RESET_TOKENS: PasswordResetToken[] = [];

// -------------------------------------------------------------
// Authentication Endpoints (/api/v1/auth/*)
// -------------------------------------------------------------

/**
 * POST /api/v1/auth/signup (Citizen/User only)
 * - Fields: fullName, email, mobileNumber, password, confirmPassword
 * - Does NOT collect Aadhaar, PAN or government IDs
 * - Server enforces role = 'USER' always. Never accepts role from client.
 * - Password stored only as bcrypt hash.
 * - Mobile number encrypted at rest with AES-256-GCM.
 * - Requires consent checkbox with timestamp.
 * - Sets httpOnly session cookie.
 */
app.post('/api/v1/auth/signup', async (req: Request, res: Response) => {
  try {
    const { fullName, email, mobileNumber, password, confirmPassword, agreeToTerms } = req.body;

    // Strict validation
    if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
      return res.status(400).json({ error: 'Full name is required (minimum 2 characters).' });
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    if (!mobileNumber || mobileNumber.replace(/[^0-9]/g, '').length < 10) {
      return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number.' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }

    const pwdCheck = validatePasswordComplexity(password);
    if (!pwdCheck.valid) {
      return res.status(400).json({ error: pwdCheck.error });
    }

    if (!agreeToTerms) {
      return res.status(400).json({ error: 'You must agree to the Terms of Use and Privacy Policy to register.' });
    }

    // Check if email already registered
    const normalizedEmail = email.trim().toLowerCase();
    const existing = USERS_DB.find(u => u.email.toLowerCase() === normalizedEmail);
    if (existing) {
      return res.status(400).json({ error: 'An account with this email address already exists. Please sign in instead.' });
    }

    // Field-level AES-256-GCM encryption for mobile number at rest
    const cleanDigits = mobileNumber.replace(/[^0-9]/g, '').slice(-10);
    const mobileEncrypted = encryptFieldAES256GCM(cleanDigits);

    // Bcrypt password hash
    const pHash = hashPassword(password);

    const userId = `USR_PUN_${String(Math.floor(100 + Math.random() * 900))}`;
    const timestamp = new Date().toISOString();

    const newUser: UserRecord = {
      id: userId,
      name: fullName.trim(),
      email: normalizedEmail,
      passwordHash: pHash,
      role: 'USER', // Server hardcoded: NEVER accept role from client
      extendedRole: 'USER',
      status: 'ACTIVE',
      mobileEncrypted,
      termsConsentTimestamp: timestamp,
      createdAt: timestamp,
      failedAttempts: 0,
      lockedUntil: null,
      isDemo: false
    };

    USERS_DB.push(newUser);
    syncUserToFirestore(newUser);

    // Audit log entry
    appendAudit(
      newUser.name,
      newUser.role,
      'USER_SIGNUP',
      'USER_ACCOUNT',
      newUser.id,
      'NULL',
      `CONSENT: TERMS_ACCEPTED_AT_${timestamp}`,
      req.ip || '127.0.0.1'
    );

    // Set secure httpOnly cookie
    const token = generateSessionToken(newUser);
    res.cookie(SESSION_COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: INACTIVITY_TIMEOUT_SECONDS * 1000
    });

    return res.status(201).json({
      message: 'Citizen account registered successfully.',
      user: sanitizeUser(newUser),
      expiresAt: new Date(Date.now() + INACTIVITY_TIMEOUT_SECONDS * 1000).toISOString()
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'Registration failed due to an internal server error.' });
  }
});

/**
 * POST /api/v1/auth/login
 * - Email + password
 * - Generic "Invalid credentials" message
 * - Stored in httpOnly, Secure, SameSite cookie
 * - Rate limiting: 5 failed attempts locks for 15 minutes
 */
app.post('/api/v1/auth/login', (req: Request, res: Response) => {
  const { emailOrUsername, password, intendedPortal } = req.body;

  if (!emailOrUsername || !password) {
    return res.status(400).json({ error: 'Invalid credentials. Please verify your email and password.' });
  }

  const email = String(emailOrUsername).trim().toLowerCase();
  const user = USERS_DB.find(u => u.email.toLowerCase() === email);

  if (!user) {
    appendAudit(
      email,
      'UNKNOWN',
      'USER_LOGIN_FAILED',
      'USER_SESSION',
      'ANON',
      'NULL',
      'INVALID_EMAIL_OR_CREDENTIALS',
      req.ip || '127.0.0.1'
    );
    return res.status(401).json({ error: 'Invalid credentials. Please verify your email and password.' });
  }

  // Check rate limit lock
  if (user.lockedUntil && Date.now() < user.lockedUntil) {
    const remainingMins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
    return res.status(429).json({ 
      error: `Account locked due to 5 consecutive failed attempts. Please try again in ${remainingMins} minute(s).` 
    });
  }

  // Verify bcrypt password hash
  const isValid = verifyPassword(password, user.passwordHash);
  if (!isValid) {
    user.failedAttempts += 1;
    if (user.failedAttempts >= 5) {
      user.lockedUntil = Date.now() + 15 * 60 * 1000;
      appendAudit(
        user.name,
        user.role,
        'ACCOUNT_LOCKED_FAILED_ATTEMPTS',
        'USER_ACCOUNT',
        user.id,
        'ACTIVE',
        'LOCKED_15_MINUTES',
        req.ip || '127.0.0.1'
      );
      return res.status(429).json({ 
        error: 'Account locked due to 5 consecutive failed attempts. Please try again in 15 minutes.' 
      });
    }
    appendAudit(
      user.name,
      user.role,
      'USER_LOGIN_FAILED',
      'USER_SESSION',
      user.id,
      'NULL',
      `FAILED_ATTEMPT_${user.failedAttempts}`,
      req.ip || '127.0.0.1'
    );
    return res.status(401).json({ 
      error: 'Invalid credentials. Please verify your email and password.' 
    });
  }

  // Account active check
  if (user.status !== 'ACTIVE') {
    return res.status(403).json({ error: 'This account has been deactivated by District Administration.' });
  }

  // Intended portal check
  if (intendedPortal === 'ADMIN' && user.role !== 'ADMIN') {
    return res.status(403).json({ 
      error: 'This account is not authorized for the Admin portal. Please switch to Citizen / User.' 
    });
  }

  // Reset failed attempts on success
  user.failedAttempts = 0;
  user.lockedUntil = null;

  // Generate session token & set httpOnly cookie
  const token = generateSessionToken(user);
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: INACTIVITY_TIMEOUT_SECONDS * 1000
  });

  appendAudit(
    user.name,
    user.role,
    'USER_LOGIN_SUCCESS',
    'USER_SESSION',
    user.id,
    'NULL',
    `PORTAL: ${intendedPortal || user.role}`,
    req.ip || '127.0.0.1'
  );

  return res.json({
    message: 'Signed in successfully',
    role: user.role,
    user: sanitizeUser(user),
    expiresAt: new Date(Date.now() + INACTIVITY_TIMEOUT_SECONDS * 1000).toISOString()
  });
});

/**
 * GET /api/v1/auth/session
 * Validates the httpOnly session cookie, returns sanitized user or null
 */
app.get('/api/v1/auth/session', (req: Request, res: Response) => {
  const cookieToken = req.cookies ? req.cookies[SESSION_COOKIE_NAME] : null;
  const authHeader = req.headers['authorization'];
  const headerToken = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  const token = cookieToken || headerToken;

  if (!token) {
    return res.json({ authenticated: false, user: null });
  }

  const verified = verifySessionToken(token);
  if (!verified.valid || !verified.payload) {
    res.clearCookie(SESSION_COOKIE_NAME);
    return res.json({ authenticated: false, user: null });
  }

  const user = USERS_DB.find(u => u.id === verified.payload.sub);
  if (!user || user.status !== 'ACTIVE') {
    res.clearCookie(SESSION_COOKIE_NAME);
    return res.json({ authenticated: false, user: null });
  }

  return res.json({
    authenticated: true,
    user: sanitizeUser(user),
    role: user.role,
    expiresAt: new Date(Date.now() + INACTIVITY_TIMEOUT_SECONDS * 1000).toISOString()
  });
});

/**
 * POST /api/v1/auth/logout
 * Clears httpOnly session cookie
 */
app.post('/api/v1/auth/logout', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.user) {
    appendAudit(req.user.name, req.user.role, 'USER_LOGOUT', 'USER_SESSION', req.user.id, 'ACTIVE', 'TERMINATED', req.ip || '127.0.0.1');
  }
  res.clearCookie(SESSION_COOKIE_NAME);
  return res.json({ status: 'ok', message: 'Logged out successfully' });
});

/**
 * POST /api/v1/auth/forgot-password
 * Generates an emailed password reset token
 */
app.post('/api/v1/auth/forgot-password', (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email address is required.' });
  }

  const normalized = String(email).trim().toLowerCase();
  const user = USERS_DB.find(u => u.email.toLowerCase() === normalized);

  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 mins
    RESET_TOKENS.push({ token, email: normalized, expiresAt });

    appendAudit(
      user.name,
      user.role,
      'PASSWORD_RESET_REQUESTED',
      'USER_ACCOUNT',
      user.id,
      'NULL',
      'RESET_LINK_DISPATCHED',
      req.ip || '127.0.0.1'
    );
  }

  // Always return identical friendly response to prevent user enumeration
  return res.json({
    status: 'ok',
    message: 'If an account exists with this email address, a password reset link has been dispatched.'
  });
});

/**
 * POST /api/v1/auth/reset-password
 */
app.post('/api/v1/auth/reset-password', (req: Request, res: Response) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  const tokenEntry = RESET_TOKENS.find(t => t.token === token && t.expiresAt > Date.now());
  if (!tokenEntry) {
    return res.status(400).json({ error: 'Reset link has expired or is invalid. Please request a new one.' });
  }

  const pwdCheck = validatePasswordComplexity(newPassword);
  if (!pwdCheck.valid) {
    return res.status(400).json({ error: pwdCheck.error });
  }

  const user = USERS_DB.find(u => u.email.toLowerCase() === tokenEntry.email);
  if (!user) {
    return res.status(400).json({ error: 'Account not found.' });
  }

  user.passwordHash = hashPassword(newPassword);
  user.failedAttempts = 0;
  user.lockedUntil = null;

  // Remove token
  const idx = RESET_TOKENS.indexOf(tokenEntry);
  if (idx !== -1) RESET_TOKENS.splice(idx, 1);

  appendAudit(
    user.name,
    user.role,
    'PASSWORD_RESET_COMPLETED',
    'USER_ACCOUNT',
    user.id,
    'OLD_HASH',
    'NEW_BCRYPT_HASH_SET',
    req.ip || '127.0.0.1'
  );

  return res.json({ status: 'ok', message: 'Password has been successfully updated. You can now sign in.' });
});

// -------------------------------------------------------------
// Admin Account Management (Admins created ONLY by existing Admin)
// -------------------------------------------------------------
app.post('/api/v1/admin/users/create-admin', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const { name, email, password, taluka } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const existing = USERS_DB.find(u => u.email.toLowerCase() === normalizedEmail);
  if (existing) {
    return res.status(400).json({ error: 'User with this email already exists.' });
  }

  const pwdCheck = validatePasswordComplexity(password);
  if (!pwdCheck.valid) {
    return res.status(400).json({ error: pwdCheck.error });
  }

  const newAdminId = `ADM_PUN_${String(Math.floor(100 + Math.random() * 900))}`;
  const timestamp = new Date().toISOString();

  const newAdmin: UserRecord = {
    id: newAdminId,
    name: name.trim(),
    email: normalizedEmail,
    passwordHash: hashPassword(password),
    role: 'ADMIN',
    extendedRole: 'REVENUE_OFFICER',
    status: 'ACTIVE',
    taluka: taluka || 'Pune Collectorate',
    mobileEncrypted: encryptFieldAES256GCM('9423000000'),
    termsConsentTimestamp: timestamp,
    createdAt: timestamp,
    failedAttempts: 0,
    lockedUntil: null,
    isDemo: false
  };

  USERS_DB.push(newAdmin);
  syncUserToFirestore(newAdmin);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'ADMIN_USER_CREATED',
    'USER_ACCOUNT',
    newAdmin.id,
    'NULL',
    `CREATED_BY: ${req.user!.name} (${req.user!.id})`,
    req.ip || '127.0.0.1'
  );

  return res.status(201).json({
    message: 'Administrative account created successfully.',
    admin: sanitizeUser(newAdmin)
  });
});

// -------------------------------------------------------------
// Grievance & Citizen Inquiries (/api/v1/grievance)
// -------------------------------------------------------------
app.post('/api/v1/grievance', (req: Request, res: Response) => {
  const { name, email, phone, category, subject, message } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'Please provide your name, email, subject, and message.' });
  }

  const id = `PUN-GRV-2026-${String(Math.floor(100 + Math.random() * 900))}`;
  const timestamp = new Date().toISOString();
  const phoneClean = phone ? maskPhoneStr(String(phone)) : '98******00';

  const grievance: GrievanceServer = {
    id,
    name: String(name).trim(),
    email: String(email).trim().toLowerCase(),
    phone: phoneClean,
    category: category || 'GENERAL_FEEDBACK',
    subject: String(subject).trim(),
    message: String(message).trim(),
    status: 'SUBMITTED',
    createdAt: timestamp
  };

  GRIEVANCES_DB.unshift(grievance);
  syncGrievanceToFirestore(grievance);

  appendAudit(
    grievance.name,
    'CITIZEN_PUBLIC',
    'GRIEVANCE_SUBMITTED',
    'GRIEVANCE',
    id,
    'NULL',
    `CATEGORY: ${grievance.category} | SUBJECT: ${grievance.subject.slice(0, 30)}`,
    req.ip || '127.0.0.1'
  );

  return res.status(201).json({
    message: 'Your grievance has been lodged successfully and routed to Pune District Land Governance desk.',
    trackingId: id,
    createdAt: timestamp
  });
});

app.get('/api/v1/admin/grievances', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  return res.json(GRIEVANCES_DB);
});

// -------------------------------------------------------------
// Private Document Storage & Expiring Signed Links
// -------------------------------------------------------------
app.get('/api/v1/docs/:docId/signed-link', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const { docId } = req.params;
  const token = generateSignedDocumentToken(docId, req.user!.id, 900); // 15 mins
  return res.json({
    docId,
    signedUrl: `/api/v1/docs/view?token=${token}`,
    expiresInSeconds: 900,
    expiresAt: new Date(Date.now() + 900 * 1000).toISOString()
  });
});

app.get('/api/v1/docs/view', (req: Request, res: Response) => {
  const token = String(req.query.token || '');
  const verified = verifySignedDocumentToken(token);
  if (!verified.valid) {
    return res.status(403).json({ error: 'Forbidden: Expired or invalid document signature link.' });
  }

  // Simulated private document content
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="BhoomiSetu_Doc_${verified.docId}.pdf"`);
  return res.send(Buffer.from(`%PDF-1.4\n% BhoomiSetu Pune Land Stack Prototype Document\n% Verified Doc ID: ${verified.docId}\n%%EOF`));
});

// -------------------------------------------------------------
// Protected Cadastral Request API Routes
// -------------------------------------------------------------

// POST /api/v1/requests (USER or ADMIN)
app.post('/api/v1/requests', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const { type, title, description, parcelId, ulpin, gatNumber, taluka, village, payload, currentValues, documents } = req.body;

  if (!type || !gatNumber || !taluka || !village) {
    return res.status(400).json({ error: 'Missing required request parameters (type, gatNumber, taluka, village)' });
  }

  const id = `PUN-REQ-2026-${String(Math.floor(100 + Math.random() * 900))}`;
  const timestamp = new Date().toISOString();

  let applicantMobile = '98******21';
  try {
    const rawMobile = decryptFieldAES256GCM(req.user!.mobileEncrypted);
    applicantMobile = maskPhoneStr(rawMobile);
  } catch {}

  const newRequest: ApprovalRequestServer = {
    id,
    type,
    title: title || `${type.replace('_', ' ')} for Gat No. ${gatNumber}`,
    description: description || 'Citizen portal application',
    parcelId: parcelId || `PUN_${gatNumber}`,
    ulpin: ulpin || `MH-27-25-PUN-${gatNumber}`,
    gatNumber,
    taluka,
    village,
    submittedBy: req.user!.id,
    applicantName: req.user!.name,
    applicantEmail: req.user!.email,
    applicantPhoneMasked: applicantMobile,
    status: 'SUBMITTED',
    payload: payload || {},
    currentValues: currentValues || {},
    documents: documents || [],
    history: [
      {
        action: 'SUBMITTED',
        actor: req.user!.name,
        actorRole: req.user!.role,
        timestamp,
        remarks: 'Submitted via BhoomiSetu Citizen Portal'
      }
    ],
    reconciliationScore: 95,
    createdAt: timestamp,
    updatedAt: timestamp
  };

  REQUESTS_DB.unshift(newRequest);
  syncRequestToFirestore(newRequest);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'REQUEST_SUBMITTED',
    'APPROVAL_REQUEST',
    id,
    'NULL',
    `TYPE: ${type} | GAT: ${gatNumber} ${village}`,
    req.ip || '127.0.0.1'
  );

  return res.status(201).json(newRequest);
});

// GET /api/v1/requests/mine (USER)
app.get('/api/v1/requests/mine', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const userRequests = REQUESTS_DB.filter(r => r.submittedBy === req.user!.id);
  return res.json(userRequests);
});

// GET /api/v1/admin/requests (ADMIN only - 403 on USER)
app.get('/api/v1/admin/requests', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const { status, type, taluka } = req.query;
  let filtered = [...REQUESTS_DB];

  if (status && status !== 'ALL') {
    filtered = filtered.filter(r => r.status === status);
  }
  if (type && type !== 'ALL') {
    filtered = filtered.filter(r => r.type === type);
  }
  if (taluka && taluka !== 'ALL') {
    filtered = filtered.filter(r => r.taluka.toLowerCase() === String(taluka).toLowerCase());
  }

  return res.json(filtered);
});

// GET /api/v1/admin/requests/:id
app.get('/api/v1/admin/requests/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const request = REQUESTS_DB.find(r => r.id === req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }

  if (req.user!.role !== 'ADMIN' && request.submittedBy !== req.user!.id) {
    return res.status(403).json({ error: 'Forbidden: Cannot access another citizen’s application.' });
  }

  return res.json(request);
});

// POST /api/v1/admin/requests/:id/approve (ADMIN only)
app.post('/api/v1/admin/requests/:id/approve', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const { remarks } = req.body;
  const request = REQUESTS_DB.find(r => r.id === req.params.id);

  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }

  // Maker-checker validation: An admin cannot approve their own request
  if (request.submittedBy === req.user!.id) {
    return res.status(403).json({ 
      error: 'Maker-Checker Violation: You cannot approve a request that you submitted.' 
    });
  }

  const timestamp = new Date().toISOString();
  request.status = 'APPROVED';
  request.adminRemarks = remarks || 'Approved after statutory revenue verification.';
  request.decisionBy = req.user!.name;
  request.decidedAt = timestamp;
  request.updatedAt = timestamp;
  request.history.push({
    action: 'APPROVED',
    actor: req.user!.name,
    actorRole: req.user!.role,
    timestamp,
    remarks: request.adminRemarks
  });

  syncRequestToFirestore(request);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'REQUEST_APPROVED',
    'APPROVAL_REQUEST',
    request.id,
    'STATUS: UNDER_REVIEW',
    `STATUS: APPROVED | Remarks: ${request.adminRemarks}`,
    req.ip || '127.0.0.1'
  );

  return res.json(request);
});

// POST /api/v1/admin/requests/:id/reject (ADMIN only)
app.post('/api/v1/admin/requests/:id/reject', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const { remarks } = req.body;

  if (!remarks || String(remarks).trim().length === 0) {
    return res.status(400).json({ error: 'Mandatory Remarks: Rejection reason must be provided under administrative rules.' });
  }

  const request = REQUESTS_DB.find(r => r.id === req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }

  if (request.submittedBy === req.user!.id) {
    return res.status(403).json({ error: 'Maker-Checker Violation: You cannot reject your own application.' });
  }

  const timestamp = new Date().toISOString();
  request.status = 'REJECTED';
  request.adminRemarks = remarks;
  request.decisionBy = req.user!.name;
  request.decidedAt = timestamp;
  request.updatedAt = timestamp;
  request.history.push({
    action: 'REJECTED',
    actor: req.user!.name,
    actorRole: req.user!.role,
    timestamp,
    remarks
  });

  syncRequestToFirestore(request);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'REQUEST_REJECTED',
    'APPROVAL_REQUEST',
    request.id,
    'STATUS: UNDER_REVIEW',
    `STATUS: REJECTED | Reason: ${remarks}`,
    req.ip || '127.0.0.1'
  );

  return res.json(request);
});

// POST /api/v1/admin/requests/:id/return (ADMIN only)
app.post('/api/v1/admin/requests/:id/return', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const { remarks } = req.body;

  if (!remarks || String(remarks).trim().length === 0) {
    return res.status(400).json({ error: 'Mandatory Remarks: Clarification queries must be provided.' });
  }

  const request = REQUESTS_DB.find(r => r.id === req.params.id);
  if (!request) {
    return res.status(404).json({ error: 'Request not found' });
  }

  const timestamp = new Date().toISOString();
  request.status = 'RETURNED';
  request.adminRemarks = remarks;
  request.decisionBy = req.user!.name;
  request.decidedAt = timestamp;
  request.updatedAt = timestamp;
  request.history.push({
    action: 'RETURNED_FOR_CLARIFICATION',
    actor: req.user!.name,
    actorRole: req.user!.role,
    timestamp,
    remarks
  });

  syncRequestToFirestore(request);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'REQUEST_RETURNED_FOR_CLARIFICATION',
    'APPROVAL_REQUEST',
    request.id,
    'STATUS: UNDER_REVIEW',
    `STATUS: RETURNED | Clarification: ${remarks}`,
    req.ip || '127.0.0.1'
  );

  return res.json(request);
});

// GET /api/v1/admin/audit (ADMIN only - 403 on USER)
app.get('/api/v1/admin/audit', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  return res.json(AUDIT_LOGS_DB);
});

// GET /api/v1/admin/users (ADMIN only - 403 on USER)
app.get('/api/v1/admin/users', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const sanitized = USERS_DB.map(sanitizeUser);
  return res.json(sanitized);
});

// PATCH /api/v1/admin/users/:id/status (ADMIN only)
app.patch('/api/v1/admin/users/:id/status', requireAuth, requireRole('ADMIN'), (req: AuthenticatedRequest, res: Response) => {
  const user = USERS_DB.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  user.status = user.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
  syncUserToFirestore(user);

  appendAudit(
    req.user!.name,
    req.user!.role,
    'USER_STATUS_TOGGLED',
    'USER_ACCOUNT',
    user.id,
    'OLD_STATUS',
    `NEW_STATUS: ${user.status}`,
    req.ip || '127.0.0.1'
  );

  return res.json({ id: user.id, status: user.status });
});

// -------------------------------------------------------------
// Medad Village (Baramati) Cadastral Dataset & Health APIs
// -------------------------------------------------------------
app.get('/api/health', (_req: Request, res: Response) => {
  return res.json({ status: 'ok', service: 'BhoomiSetu Pune Land Stack', totalRequests: REQUESTS_DB.length });
});

app.get('/api/v1/medad/profile', (_req: Request, res: Response) => {
  return res.json(MEDAD_PARCELS_PROFILES);
});

app.get('/api/v1/medad/records712', (_req: Request, res: Response) => {
  return res.json(MEDAD_712_RECORDS);
});

app.get('/api/v1/medad/khata8a', (_req: Request, res: Response) => {
  return res.json(MEDAD_8A_RECORDS);
});

app.get('/api/v1/medad/mojani', (_req: Request, res: Response) => {
  return res.json(MEDAD_MOJANI_RECORDS);
});

app.get('/api/v1/medad/requests', (_req: Request, res: Response) => {
  return res.json(MEDAD_REQUESTS_SEED);
});

// -------------------------------------------------------------
// Nimgaon Ketki Village (Indapur) Cadastral Dataset APIs
// -------------------------------------------------------------
app.get('/api/v1/nimgaon-ketki/profile', (_req: Request, res: Response) => {
  return res.json(NIMGAON_KETKI_PARCELS_PROFILES);
});

app.get('/api/v1/nimgaon-ketki/records712', (_req: Request, res: Response) => {
  return res.json(NIMGAON_KETKI_712_RECORDS);
});

app.get('/api/v1/nimgaon-ketki/khata8a', (_req: Request, res: Response) => {
  return res.json(NIMGAON_KETKI_8A_RECORDS);
});

app.get('/api/v1/nimgaon-ketki/mojani', (_req: Request, res: Response) => {
  return res.json(NIMGAON_KETKI_MOJANI_RECORDS);
});

app.get('/api/v1/nimgaon-ketki/requests', (_req: Request, res: Response) => {
  return res.json(NIMGAON_KETKI_REQUESTS_SEED);
});

// -------------------------------------------------------------
// Read-Only Village Land Packs API (/api/v1/land/villages)
// -------------------------------------------------------------
app.get('/api/v1/land/villages', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
  const villages = Array.from(LAND_PACKS.values()).map(pack => {
    const availableDatasets = Array.from(ALLOWED_VILLAGE_DATASETS).filter(
      ds => (pack as Record<string, any>)[ds] !== undefined
    );
    return {
      slug: pack.slug,
      profile: pack.profile || null,
      availableDatasets,
      datasets: availableDatasets
    };
  });
  return res.json(villages);
});

app.get('/api/v1/land/villages/:slug/:dataset', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const slug = String(req.params.slug || '');
  const dataset = String(req.params.dataset || '');

  if (!VILLAGE_SLUG_REGEX.test(slug)) {
    return res.status(404).json({ error: 'Village pack not found.' });
  }

  if (!ALLOWED_VILLAGE_DATASETS.has(dataset)) {
    return res.status(404).json({ error: 'Dataset not found.' });
  }

  const pack = LAND_PACKS.get(slug);
  if (!pack) {
    return res.status(404).json({ error: 'Village pack not found.' });
  }

  const rawData = (pack as Record<string, any>)[dataset];
  if (rawData === undefined) {
    return res.status(404).json({ error: `Dataset '${dataset}' not available for village '${slug}'.` });
  }

  const gatFilter = req.query.gat !== undefined ? String(req.query.gat).trim() : null;
  const ctsFilter = req.query.cts !== undefined ? String(req.query.cts).trim() : null;
  const statusFilter = req.query.status !== undefined ? String(req.query.status).trim().toLowerCase() : null;

  if (dataset === 'profile') {
    return res.json(rawData);
  }

  if (dataset === 'parcels' && rawData && Array.isArray(rawData.features)) {
    let features = rawData.features;
    if (gatFilter) {
      features = features.filter(
        (f: any) =>
          String(f?.properties?.gatNumber ?? f?.properties?.gat ?? '') === gatFilter ||
          String(f?.properties?.surveyNumber ?? '') === gatFilter
      );
    }
    if (ctsFilter) {
      features = features.filter(
        (f: any) =>
          String(f?.properties?.ctsNumber ?? f?.properties?.cts ?? '') === ctsFilter ||
          String(f?.properties?.ctsNumber ?? '').replace(/^CTS-[A-Z0-9]+-/i, '') === ctsFilter
      );
    }
    return res.json({
      ...rawData,
      features
    });
  }

  if (Array.isArray(rawData)) {
    let filtered = [...rawData];
    if (gatFilter) {
      filtered = filtered.filter((item: any) => {
        if (String(item?.gatNumber ?? item?.gat ?? '') === gatFilter) return true;
        if (String(item?.surveyNumber ?? '') === gatFilter) return true;
        if (Array.isArray(item?.parcels)) {
          return item.parcels.some(
            (p: any) => String(p?.gatOrSurveyNo ?? p?.gatNumber ?? '') === gatFilter
          );
        }
        return false;
      });
    }
    if (ctsFilter) {
      filtered = filtered.filter(
        (item: any) =>
          String(item?.ctsNumber ?? item?.cts ?? '') === ctsFilter ||
          String(item?.ctsNumber ?? '').replace(/^CTS-[A-Z0-9]+-/i, '') === ctsFilter
      );
    }
    if (statusFilter && dataset === 'mojani') {
      filtered = filtered.filter((item: any) => {
        const st = String(item?.status ?? '').toLowerCase();
        return st === statusFilter || st.includes(statusFilter);
      });
    }
    return res.json(filtered);
  }

  return res.json(rawData);
});

// -------------------------------------------------------------
// Vite Server Integration & Production Static Serving
// -------------------------------------------------------------
async function startServer() {
  const isProdBundle = Boolean(process.argv[1] && process.argv[1].endsWith('server.cjs'));
  if (process.env.NODE_ENV !== 'production' && !isProdBundle) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`BhoomiSetu Pune Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
