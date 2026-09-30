/**
 * Excalidraw Diagram Generator for Loki Agency Credential Manager
 * Generates 4 comprehensive diagrams:
 * 1. docs/diagrams/architecture-end-to-end.excalidraw
 * 2. docs/diagrams/timekeeper-administrative-flow.excalidraw
 * 3. docs/diagrams/agent-credential-flow.excalidraw
 * 4. docs/diagrams/variant-restricted-flow.excalidraw
 */

import fs from 'fs';
import path from 'path';

function createBaseDiagram(elements) {
  return {
    type: "excalidraw",
    version: 2,
    source: "https://excalidraw.com",
    elements,
    appState: {
      viewBackgroundColor: "#0f172a", // Sleek dark theme
      gridSize: 20
    }
  };
}

let elementIdCounter = 1000;
function getId(prefix = "el") {
  elementIdCounter++;
  return `${prefix}_${elementIdCounter}`;
}

function makeBox(id, x, y, w, h, text, bg = "#1e293b", stroke = "#94a3b8", fontSize = 14, align = "center") {
  return {
    id,
    type: "rectangle",
    x,
    y,
    width: w,
    height: h,
    angle: 0,
    strokeColor: stroke,
    backgroundColor: bg,
    fillStyle: "solid",
    strokeWidth: 2,
    strokeStyle: "solid",
    roughness: 1,
    opacity: 100,
    groupIds: [],
    frameId: null,
    index: "a" + elementIdCounter,
    roundness: { type: 3 },
    seed: Math.floor(Math.random() * 1000000),
    version: 1,
    versionNonce: Math.floor(Math.random() * 1000000),
    isDeleted: false,
    boundElements: null,
    updated: Date.now(),
    link: null,
    locked: false,
    text,
    fontSize,
    fontFamily: 1,
    textAlign: align,
    verticalAlign: "middle"
  };
}

function makeDiamond(id, x, y, w, h, text, bg = "#3b2d18", stroke = "#f59e0b", fontSize = 13) {
  return {
    id,
    type: "diamond",
    x,
    y,
    width: w,
    height: h,
    angle: 0,
    strokeColor: stroke,
    backgroundColor: bg,
    fillStyle: "solid",
    strokeWidth: 2,
    strokeStyle: "solid",
    roughness: 1,
    opacity: 100,
    groupIds: [],
    frameId: null,
    index: "a" + elementIdCounter,
    seed: Math.floor(Math.random() * 1000000),
    version: 1,
    versionNonce: Math.floor(Math.random() * 1000000),
    isDeleted: false,
    boundElements: null,
    updated: Date.now(),
    link: null,
    locked: false,
    text,
    fontSize,
    fontFamily: 1,
    textAlign: "center",
    verticalAlign: "middle"
  };
}

function makeArrow(id, x, y, dx, dy, stroke = "#38bdf8", text = "") {
  return {
    id,
    type: "arrow",
    x,
    y,
    width: Math.abs(dx),
    height: Math.abs(dy),
    angle: 0,
    strokeColor: stroke,
    backgroundColor: "transparent",
    fillStyle: "solid",
    strokeWidth: 2,
    strokeStyle: "solid",
    roughness: 1,
    opacity: 100,
    groupIds: [],
    frameId: null,
    index: "a" + elementIdCounter,
    roundness: { type: 2 },
    seed: Math.floor(Math.random() * 1000000),
    version: 1,
    versionNonce: Math.floor(Math.random() * 1000000),
    isDeleted: false,
    boundElements: null,
    updated: Date.now(),
    link: null,
    locked: false,
    points: [
      [0, 0],
      [dx, dy]
    ],
    endArrowhead: "arrow",
    text: text || undefined,
    fontSize: 12
  };
}

function makeText(id, x, y, text, fontSize = 16, stroke = "#f8fafc") {
  return {
    id,
    type: "text",
    x,
    y,
    width: text.length * (fontSize * 0.6),
    height: fontSize * 1.4,
    angle: 0,
    strokeColor: stroke,
    backgroundColor: "transparent",
    fillStyle: "solid",
    strokeWidth: 1,
    strokeStyle: "solid",
    roughness: 1,
    opacity: 100,
    groupIds: [],
    frameId: null,
    index: "a" + elementIdCounter,
    roundness: null,
    seed: Math.floor(Math.random() * 1000000),
    version: 1,
    versionNonce: Math.floor(Math.random() * 1000000),
    isDeleted: false,
    boundElements: null,
    updated: Date.now(),
    link: null,
    locked: false,
    text,
    fontSize,
    fontFamily: 1,
    textAlign: "left",
    verticalAlign: "top"
  };
}

// -------------------------------------------------------------
// DIAGRAM 1: FULL END-TO-END ARCHITECTURE
// -------------------------------------------------------------
function generateArchitectureDiagram() {
  const elements = [];
  
  // Title & Header
  elements.push(makeText(getId("t"), 80, 40, "LOKI VAULT: FULL END-TO-END ZERO-KNOWLEDGE ARCHITECTURE", 24, "#38bdf8"));
  elements.push(makeText(getId("t"), 80, 75, "Strict Boundary Demarcation: Plaintext | Cryptographic Layer | Authenticated Ciphertext Storage", 14, "#94a3b8"));

  // Zones / Containers
  // 1. Plaintext Client Boundary (Green)
  elements.push(makeBox(getId("zone"), 60, 120, 340, 760, "", "#064e3b", "#10b981"));
  elements.push(makeText(getId("zt"), 80, 140, "ZONE 1: PLAINTEXT BOUNDARY (Client Memory Only)", 14, "#34d399"));
  elements.push(makeBox(getId("b"), 90, 180, 280, 70, "User (Timekeeper / Agent / Variant)\nBrowser Interface / Input Form", "#022c22", "#059669", 13));
  elements.push(makeBox(getId("b"), 90, 280, 280, 70, "Local Memory Cache (Zeroized on Lock)\nPlaintext Passwords NEVER Written to Disk", "#022c22", "#059669", 12));
  elements.push(makeBox(getId("b"), 90, 380, 280, 70, "Auto-Clear Clipboard Engine\n30s Timer Clears Copied Plaintext", "#022c22", "#059669", 12));
  elements.push(makeBox(getId("b"), 90, 480, 280, 70, "SessionStorage Temporary Tab DEK\nErased on Tab Close / Logout / Lock", "#022c22", "#059669", 12));
  elements.push(makeBox(getId("b"), 90, 580, 280, 70, "Client-Side SVG Icon Catalog\nInstagram, FB, Google Ads, AWS, Stripe", "#022c22", "#059669", 12));
  elements.push(makeBox(getId("b"), 90, 680, 280, 80, "Emergency Lockdown Module\nPurges Session DEK & Memory State", "#022c22", "#059669", 12));

  // 2. Cryptographic Security Engine (Yellow/Purple)
  elements.push(makeBox(getId("zone"), 440, 120, 360, 760, "", "#3b0764", "#c084fc"));
  elements.push(makeText(getId("zt"), 460, 140, "ZONE 2: CRYPTOGRAPHIC ENGINE (Libsodium / WebCrypto)", 14, "#e879f9"));
  elements.push(makeBox(getId("b"), 470, 180, 300, 75, "Argon2id (Node) / PBKDF2-SHA512 (Browser)\nKEK Derivation (64MB, 3 Time, 100K iter)\nMaster Password -> 256-bit KEK", "#581c87", "#c084fc", 12));
  elements.push(makeBox(getId("b"), 470, 280, 300, 75, "Curve25519 Asymmetric Key Exchange\ncrypto_box_keypair (Public / Private Key)\nWrapped DEK Sharing Between Users", "#581c87", "#c084fc", 12));
  elements.push(makeBox(getId("b"), 470, 380, 300, 75, "XChaCha20-Poly1305 Authenticated AEAD\n24-Byte Fresh Random Nonce per Operation\nGuarantees Tamper Detection & Secrecy", "#581c87", "#c084fc", 12));
  elements.push(makeBox(getId("b"), 470, 480, 300, 75, "User Login Password Hasher (Argon2id / PBKDF2)\nSalted 16-byte Non-Reversible Hash\nStrictly Never Stored in Plaintext", "#581c87", "#c084fc", 12));
  elements.push(makeBox(getId("b"), 470, 580, 300, 75, "JWT Session Signature (RS256/HS256)\nRole Claims (timekeeper, agent, variant)\nSubject, OrgID, Expiry, Revocation Check", "#581c87", "#c084fc", 12));
  elements.push(makeBox(getId("b"), 470, 680, 300, 80, "Zero-Knowledge DEK Generator\n32-Byte Cryptographically Secure DEK\nKey Zeroization & Memory Overwrite", "#581c87", "#c084fc", 12));

  // 3. Authenticated Ciphertext & Cloud Storage (Blue/Slate)
  elements.push(makeBox(getId("zone"), 840, 120, 380, 760, "", "#1e1b4b", "#818cf8"));
  elements.push(makeText(getId("zt"), 860, 140, "ZONE 3: AUTHENTICATED STORAGE & FIRESTORE", 14, "#a5b4fc"));
  elements.push(makeBox(getId("b"), 870, 180, 320, 75, "/clients/{clientId}/platforms/{credId}\nCiphertext (Base64) + Nonce (24 Bytes)\nNO Plaintext Credentials in Cloud DB", "#312e81", "#818cf8", 12));
  elements.push(makeBox(getId("b"), 870, 280, 320, 75, "/users/{userId} User Profiles\nrole, assignedClients, supervisingTimekeepers\npasswordHash: $pbkdf2$100000$salt$hash", "#312e81", "#818cf8", 12));
  elements.push(makeBox(getId("b"), 870, 380, 320, 75, "/deletion_requests\nPending Agent Requests awaiting Timekeeper\nReviewed timestamp, approval status", "#312e81", "#818cf8", 12));
  elements.push(makeBox(getId("b"), 870, 480, 320, 75, "/audit_logs Tamper-Evident Trail\nUser, Action, Client Scoped Timestamp\nEncrypted Audit Records & Anomaly Logs", "#312e81", "#818cf8", 12));
  elements.push(makeBox(getId("b"), 870, 580, 320, 75, "Firestore Security Rules (Strict RBAC)\ntimekeeper: read/write all in org\nagent: scoped to assignedClients/platforms\nvariant: read-only, create/delete blocked", "#312e81", "#818cf8", 11));
  elements.push(makeBox(getId("b"), 870, 680, 320, 80, "Offline LocalStorage Cache (Encrypted Only)\nStrict Zero-Plaintext Storage Filter\nAll values authenticated ciphertext only", "#312e81", "#818cf8", 12));

  // Connectors
  elements.push(makeArrow(getId("ar"), 370, 215, 70, 0, "#10b981", "Encrypt"));
  elements.push(makeArrow(getId("ar"), 770, 215, 70, 0, "#c084fc", "Write Ciphertext"));
  elements.push(makeArrow(getId("ar"), 840, 245, -70, 0, "#818cf8", "Read Ciphertext"));
  elements.push(makeArrow(getId("ar"), 440, 245, -70, 0, "#c084fc", "Decrypt In-Memory"));

  return createBaseDiagram(elements);
}

// -------------------------------------------------------------
// DIAGRAM 2: TIMEKEEPER FLOW
// -------------------------------------------------------------
function generateTimekeeperFlowDiagram() {
  const elements = [];
  
  elements.push(makeText(getId("t"), 60, 40, "TIMEKEEPER ROLE: FULL AUTHORIZATION & ADMINISTRATIVE WORKFLOW", 22, "#38bdf8"));
  elements.push(makeText(getId("t"), 60, 75, "Complete Governance Flow: User Lifecycle, Client Onboarding, Code Authorization & Supervision", 14, "#94a3b8"));

  // Flowchart Nodes
  let y = 120;
  elements.push(makeBox(getId("tk"), 450, y, 260, 60, "Timekeeper Authenticates\n(Argon2id Hash + JWT Issued)", "#1e3a8a", "#60a5fa", 13));
  elements.push(makeArrow(getId("ar"), 580, y + 60, 0, 40));
  
  y += 100;
  elements.push(makeDiamond(getId("dec"), 480, y, 200, 80, "Route Requested?", "#3b2d18", "#f59e0b", 12));
  
  // Left branch: User Management
  elements.push(makeArrow(getId("ar"), 480, y + 40, -160, 0, "#38bdf8", "Users"));
  elements.push(makeBox(getId("tk"), 140, y + 10, 260, 60, "User Management Center\nCreate Users, Assign Roles", "#1e293b", "#38bdf8", 12));
  elements.push(makeArrow(getId("ar"), 270, y + 70, 0, 40));
  elements.push(makeBox(getId("tk"), 140, y + 110, 260, 70, "Role & Supervision Setup\nAssign 1-3 Supervising Timekeepers\nConfigure Auth Code & Client Permissions", "#1e293b", "#38bdf8", 12));
  elements.push(makeArrow(getId("ar"), 270, y + 180, 0, 40));
  elements.push(makeBox(getId("tk"), 140, y + 220, 260, 60, "Administrative Password Reset\nCreator TK Overrides User Password", "#1e293b", "#38bdf8", 12));

  // Center branch: Client & Credential Lifecycle
  elements.push(makeArrow(getId("ar"), 580, y + 80, 0, 50, "#10b981", "Clients/Vaults"));
  elements.push(makeBox(getId("tk"), 450, y + 130, 260, 60, "Client Directory\nAdd Client / Manage Client Scope", "#1e293b", "#10b981", 12));
  elements.push(makeArrow(getId("ar"), 580, y + 190, 0, 40));
  elements.push(makeBox(getId("tk"), 450, y + 230, 260, 70, "Add/Edit Platform Credentials\nSelect from 15+ Rich Platform Catalogs\nDerives DEK -> XChaCha20-Poly1305 Encrypt", "#1e293b", "#10b981", 12));
  elements.push(makeArrow(getId("ar"), 580, y + 300, 0, 40));
  elements.push(makeBox(getId("tk"), 450, y + 340, 260, 60, "Direct Deletion\nPermanently Purges Client & Platform Keys", "#450a0a", "#ef4444", 12));

  // Right branch: Approvals & Audit
  elements.push(makeArrow(getId("ar"), 680, y + 40, 160, 0, "#c084fc", "Approvals/Audit"));
  elements.push(makeBox(getId("tk"), 760, y + 10, 260, 60, "Review Deletion Requests\nApprove or Reject Agent Submissions", "#1e293b", "#c084fc", 12));
  elements.push(makeArrow(getId("ar"), 890, y + 70, 0, 40));
  elements.push(makeBox(getId("tk"), 760, y + 110, 260, 60, "Approval Action Execution\nAuto-Purges Cloud & Local Credential", "#1e293b", "#c084fc", 12));
  elements.push(makeArrow(getId("ar"), 890, y + 170, 0, 40));
  elements.push(makeBox(getId("tk"), 760, y + 210, 260, 70, "Audit Trail & Anomaly Monitor\nLogs USER_CREATED, VAULT_LOCKED,\nDELETION_CODE_AUTHORIZED", "#1e293b", "#c084fc", 12));

  // Timekeeper Downgrade / Departure Handling (Bottom Container)
  elements.push(makeBox(getId("tk"), 220, 570, 720, 100, "TIMEKEEPER DOWNGRADE & DEPARTURE SECURITY ENGINE\n• Downgrade (TK -> Agent): Immediately revokes Admin JWT & invalidates admin routes\n• Supervised Agents with remaining active TKs continue uninterrupted\n• If ALL supervising TKs removed -> Agent enters restricted state (Code deletion locked)\n• Auth code of disabled Timekeeper rejected instantly via cryptographic verification", "#0f172a", "#f59e0b", 12));

  return createBaseDiagram(elements);
}

// -------------------------------------------------------------
// DIAGRAM 3: AGENT FLOW
// -------------------------------------------------------------
function generateAgentFlowDiagram() {
  const elements = [];

  elements.push(makeText(getId("t"), 60, 40, "AGENT ROLE: CLIENT & PLATFORM RESTRICTED CREDENTIAL FLOW", 22, "#38bdf8"));
  elements.push(makeText(getId("t"), 60, 75, "Strict Scoping: Access Scopes, Old-Password Verification, Deletion Request & Code Execution", 14, "#94a3b8"));

  let y = 120;
  elements.push(makeBox(getId("ag"), 440, y, 280, 60, "Agent Authenticates\nRole: agent (Scoped Client & Platform Access)", "#1e3a8a", "#60a5fa", 13));
  elements.push(makeArrow(getId("ar"), 580, y + 60, 0, 40));

  y += 100;
  elements.push(makeDiamond(getId("dec"), 480, y, 200, 80, "Client Assigned?", "#3b2d18", "#f59e0b", 12));
  elements.push(makeArrow(getId("ar"), 480, y + 40, -120, 0, "#ef4444", "No"));
  elements.push(makeBox(getId("ag"), 160, y + 10, 200, 60, "Access Denied\n404 / 'No Clients Assigned'\nVault Remains Locked", "#450a0a", "#ef4444", 12));

  elements.push(makeArrow(getId("ar"), 580, y + 80, 0, 40, "#10b981", "Yes"));

  y += 120;
  elements.push(makeDiamond(getId("dec"), 470, y, 220, 80, "Platform Assigned?", "#3b2d18", "#f59e0b", 12));
  elements.push(makeArrow(getId("ar"), 690, y + 40, 120, 0, "#ef4444", "No"));
  elements.push(makeBox(getId("ag"), 810, y + 10, 200, 60, "Platform Scoped Deny\nCredential Hidden from View\nDirect Access Blocked", "#450a0a", "#ef4444", 12));

  elements.push(makeArrow(getId("ar"), 580, y + 80, 0, 40, "#10b981", "Yes"));

  // Operations Zone
  y += 120;
  elements.push(makeBox(getId("ag"), 430, y, 300, 60, "Platform Credential Card Displayed\nEncrypted Ciphertext In Storage", "#1e293b", "#38bdf8", 12));
  elements.push(makeArrow(getId("ar"), 580, y + 60, 0, 40));

  y += 100;
  elements.push(makeDiamond(getId("dec"), 460, y, 240, 80, "Operation Selected?", "#3b2d18", "#f59e0b", 12));

  // Op 1: Reveal / Copy
  elements.push(makeArrow(getId("ar"), 460, y + 40, -160, 0, "#38bdf8", "Reveal/Copy"));
  elements.push(makeBox(getId("ag"), 100, y + 10, 200, 70, "Decrypt with Vault DEK\nRender Plaintext in Memory\nCopy -> Auto-Clear in 30s", "#064e3b", "#10b981", 12));

  // Op 2: Edit
  elements.push(makeArrow(getId("ar"), 580, y + 80, 0, 50, "#f59e0b", "Edit Password"));
  elements.push(makeBox(getId("ag"), 440, y + 130, 280, 70, "Current Password Required\nVerify against known decrypted password\nIf forgotten: Request Admin Override", "#1e293b", "#f59e0b", 12));

  // Op 3: Deletion Paths
  elements.push(makeArrow(getId("ar"), 700, y + 40, 160, 0, "#ef4444", "Delete"));
  elements.push(makeBox(getId("ag"), 860, y + 10, 240, 70, "Option A: Request Deletion\nSubmits reason to supervising TKs\nStatus set to 'pending'", "#1e293b", "#38bdf8", 12));
  elements.push(makeArrow(getId("ar"), 980, y + 80, 0, 40));
  elements.push(makeBox(getId("ag"), 860, y + 120, 240, 80, "Option B: Delete with Code\nEnter Active Supervising TK Code\nVerifies authCodeHash / passwordHash\nImmediate Purge & Audit Logging", "#1e293b", "#ef4444", 12));

  return createBaseDiagram(elements);
}

// -------------------------------------------------------------
// DIAGRAM 4: VARIANT FLOW
// -------------------------------------------------------------
function generateVariantFlowDiagram() {
  const elements = [];

  elements.push(makeText(getId("t"), 60, 40, "VARIANT ROLE: RESTRICTED READ-ONLY CREDENTIAL FLOW", 22, "#38bdf8"));
  elements.push(makeText(getId("t"), 60, 75, "Strict Zero-Mutation Boundary: View/Copy Permitted, Creation, Mutation & Administrative Actions Denied", 14, "#94a3b8"));

  let y = 120;
  elements.push(makeBox(getId("va"), 450, y, 260, 60, "Variant Authenticates\nRole: variant (Read-Only Viewer)", "#1e3a8a", "#60a5fa", 13));
  elements.push(makeArrow(getId("ar"), 580, y + 60, 0, 40));

  y += 100;
  elements.push(makeDiamond(getId("dec"), 480, y, 200, 80, "Client Assigned?", "#3b2d18", "#f59e0b", 12));
  elements.push(makeArrow(getId("ar"), 480, y + 40, -120, 0, "#ef4444", "No"));
  elements.push(makeBox(getId("va"), 160, y + 10, 200, 60, "Access Denied\nNo clients assigned\nVault Empty Screen", "#450a0a", "#ef4444", 12));

  elements.push(makeArrow(getId("ar"), 580, y + 80, 0, 40, "#10b981", "Yes"));

  y += 120;
  elements.push(makeBox(getId("va"), 440, y, 280, 60, "View Assigned Platform Secrets\nDecrypt with Tab Vault DEK", "#1e293b", "#10b981", 12));
  elements.push(makeArrow(getId("ar"), 580, y + 60, 0, 40));

  y += 100;
  elements.push(makeDiamond(getId("dec"), 460, y, 240, 80, "Requested Action?", "#3b2d18", "#f59e0b", 12));

  // Allowed Actions (Left)
  elements.push(makeArrow(getId("ar"), 460, y + 40, -140, 0, "#10b981", "View / Copy"));
  elements.push(makeBox(getId("va"), 120, y + 10, 200, 60, "ALLOWED ACTION\nReveal Secret (Decrypted in-memory)\nCopy Plaintext (Cleared in 30s)", "#064e3b", "#10b981", 12));

  // Forbidden Mutations (Right)
  elements.push(makeArrow(getId("ar"), 700, y + 40, 140, 0, "#ef4444", "Mutate / Admin"));
  elements.push(makeBox(getId("va"), 840, y - 40, 280, 160, "DENIED & BLOCKED ACTIONS\n✕ Create New Client (No UI / API 403)\n✕ Add Platform Credential (Disabled)\n✕ Edit Platform Credential (Disabled)\n✕ Delete Platform Credential (Disabled)\n✕ User Management (404 Access Denied)\n✕ Timekeeper Route / Settings (404 Denied)\n✕ Administrative Override Requests", "#450a0a", "#ef4444", 12, "left"));

  // Audit Event
  elements.push(makeArrow(getId("ar"), 220, y + 70, 0, 60));
  elements.push(makeBox(getId("va"), 120, y + 130, 200, 60, "Audit Log Emitted\nSECRET_REVEALED logged\nTimestamp & User ID Captured", "#1e293b", "#38bdf8", 12));

  return createBaseDiagram(elements);
}

// -------------------------------------------------------------
// MAIN EXECUTION
// -------------------------------------------------------------
function main() {
  const outputDir = path.resolve('docs', 'diagrams');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const d1 = generateArchitectureDiagram();
  fs.writeFileSync(path.join(outputDir, 'architecture-end-to-end.excalidraw'), JSON.stringify(d1, null, 2), 'utf-8');
  console.log('✓ Created docs/diagrams/architecture-end-to-end.excalidraw');

  const d2 = generateTimekeeperFlowDiagram();
  fs.writeFileSync(path.join(outputDir, 'timekeeper-administrative-flow.excalidraw'), JSON.stringify(d2, null, 2), 'utf-8');
  console.log('✓ Created docs/diagrams/timekeeper-administrative-flow.excalidraw');

  const d3 = generateAgentFlowDiagram();
  fs.writeFileSync(path.join(outputDir, 'agent-credential-flow.excalidraw'), JSON.stringify(d3, null, 2), 'utf-8');
  console.log('✓ Created docs/diagrams/agent-credential-flow.excalidraw');

  const d4 = generateVariantFlowDiagram();
  fs.writeFileSync(path.join(outputDir, 'variant-restricted-flow.excalidraw'), JSON.stringify(d4, null, 2), 'utf-8');
  console.log('✓ Created docs/diagrams/variant-restricted-flow.excalidraw');

  console.log('\nAll 4 Excalidraw diagrams successfully generated!');
}

main();
