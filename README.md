# 🔐 Java Security Toolkit

## 🛡️ Technologies & Security

![Java](https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Maven](https://img.shields.io/badge/Maven-3.9-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white)
![JDK](https://img.shields.io/badge/JDK-17-007396?style=for-the-badge&logo=openjdk&logoColor=white)

![Login Lockout](https://img.shields.io/badge/Login%20Lockout-Brute%20Force%20Protection-2E8B57?style=flat&logo=shield&logoColor=white)
![Session Manager](https://img.shields.io/badge/Session%20Manager-UUID%20Tokens-1E90FF?style=flat&logo=key&logoColor=white)
![Rate Limiter](https://img.shields.io/badge/Rate%20Limiter-IP%20Based-FF8C00?style=flat&logo=speedtest&logoColor=white)
![SHA-256](https://img.shields.io/badge/SHA--256-Hashing-6A5ACD?style=flat&logo=letsencrypt&logoColor=white)
![HMAC](https://img.shields.io/badge/HMAC-Integrity-4682B4?style=flat&logo=databricks&logoColor=white)
![Input Validation](https://img.shields.io/badge/Input%20Validation-Whitelist%20Regex-228B22?style=flat&logo=checkmarx&logoColor=white)
![SQL Injection Demo](https://img.shields.io/badge/SQL%20Injection-Demo-B22222?style=flat&logo=mysql&logoColor=white)
![Append-Only Logs](https://img.shields.io/badge/Append--Only-Logs-008B8B?style=flat&logo=file-text&logoColor=white)
![STRIDE](https://img.shields.io/badge/STRIDE-Threat%20Model-7B1FA2?style=flat&logo=matrix&logoColor=white)
![Threat Modeling](https://img.shields.io/badge/Threat%20Modeling-Secure%20Design-5E35B1?style=flat&logo=gitbook&logoColor=white)
![Secure Coding](https://img.shields.io/badge/Secure%20Coding-Best%20Practices-2E7D32?style=flat&logo=codefactor&logoColor=white)
![Attack Mitigations](https://img.shields.io/badge/Attack-Mitigations-455A64?style=flat&logo=shield&logoColor=white)
![Authentication Flow](https://img.shields.io/badge/Auth%20Flow-Defense%20in%20Depth-1565C0?style=flat&logo=auth0&logoColor=white)
![Security Testing](https://img.shields.io/badge/Security-Testing-00897B?style=flat&logo=hackthebox&logoColor=white)

A collection of production-ready Java security implementations — BCrypt hashing, AES-256-GCM encryption, RBAC, audit logging, brute-force protection, SQL injection prevention, and STRIDE threat modelling. Built from a real Hotel PMS project. Drop these classes into any Java project to add enterprise-grade security in minutes — no Spring, no framework dependency.

Built by a cybersecurity student at NuTech as part of an OOP semester project.

---

## 📦 What's Inside

| Package | Class | What it does |
|---------|-------|-------------|
| `com.security.auth` | `PasswordManager` | BCrypt hashing (cost 12) + strength checking |
| `com.security.auth` | `LoginLockout` | Brute-force protection — locks after N failures |
| `com.security.auth` | `SessionManager` | UUID session tokens with expiry |
| `com.security.crypto` | `AESEncryption` | AES-256-GCM field-level encryption/decryption |
| `com.security.access` | `RBAC` | Role-based access control (ADMIN/STAFF/GUEST) |
| `com.security.audit` | `AuditLogger` | Append-only security audit trail to file |
| `com.security.validation` | `InputValidator` | Whitelist regex + SQL injection prevention demo |
| `com.security.threat` | `StrideModel` | STRIDE threat model with mitigations |

---

## 🚀 Quick Start

### 1. Add to your project

**Option A — Copy the files directly**
Copy the `src/main/java/com/security/` folder into your project. Change the package names to match yours.

**Option B — Maven (local install)**
```bash
git clone https://github.com/YOUR_USERNAME/java-security-toolkit.git
cd java-security-toolkit
mvn install
```
Then add to your `pom.xml`:
```xml
<dependency>
    <groupId>com.security</groupId>
    <artifactId>java-security-toolkit</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. Required dependencies in your `pom.xml`
```xml
<!-- BCrypt (for PasswordManager) -->
<dependency>
    <groupId>org.mindrot</groupId>
    <artifactId>jbcrypt</artifactId>
    <version>0.4</version>
</dependency>

<!-- SQLite (optional, for AuditLogger DB storage) -->
<dependency>
    <groupId>org.xerial</groupId>
    <artifactId>sqlite-jdbc</artifactId>
    <version>3.44.1.0</version>
</dependency>
```

---

## 📖 Usage Examples

### 🔑 BCrypt Password Hashing
```java
import com.security.auth.PasswordManager;

// When user registers — hash and store
String hash = PasswordManager.hash("Admin@123");
// Store 'hash' in your database — never the plain password

// When user logs in — verify
boolean isValid = PasswordManager.verify("Admin@123", hash); // true
boolean isWrong = PasswordManager.verify("WrongPass",  hash); // false

// Check password strength before storing
String error = PasswordManager.checkStrength("abc"); // "Password must be at least 8 characters."
String ok    = PasswordManager.checkStrength("Admin@123"); // null = strong
```

### 🔒 AES-256-GCM Encryption
```java
import com.security.crypto.AESEncryption;

// Encrypt sensitive data before saving to DB
String encrypted = AESEncryption.encrypt("PASSPORT-AB123456");
// Save 'encrypted' to your database

// Decrypt when you need to display/use it
String original = AESEncryption.decrypt(encrypted); // "PASSPORT-AB123456"

// Note: same plaintext → different ciphertext each time (random IV)
```

### 🛡️ Login Lockout (Brute Force Protection)
```java
import com.security.auth.LoginLockout;

public Optional<User> authenticate(String username, String password) {

    // Step 1: Check lockout BEFORE password verification
    if (LoginLockout.isLocked(username)) {
        long mins = LoginLockout.minutesRemaining(username);
        throw new SecurityException("Account locked. Try again in " + mins + " minutes.");
    }

    // Step 2: Verify password
    User user = userDao.findByUsername(username);
    if (PasswordManager.verify(password, user.getPasswordHash())) {
        LoginLockout.reset(username); // clear failures on success
        return Optional.of(user);
    }

    // Step 3: Record failure
    LoginLockout.recordFailure(username); // locks after MAX_ATTEMPTS (default: 5)
    return Optional.empty();
}
```

### 🎫 Session Tokens
```java
import com.security.auth.SessionManager;

// After successful login
String token = SessionManager.createSession("ahmed@hotel.com", "ADMIN");
// Send token to client (store in memory, not localStorage)

// On each request — validate token
if (!SessionManager.isValid(token)) {
    throw new SecurityException("Session expired. Please log in again.");
}

// Get user info from token
String role       = SessionManager.getRole(token);       // "ADMIN"
String identifier = SessionManager.getIdentifier(token); // "ahmed@hotel.com"

// Logout
SessionManager.invalidate(token);
```

### 👮 Role-Based Access Control (RBAC)
```java
import com.security.access.RBAC;

// Check permission (returns boolean)
if (RBAC.hasPermission(currentUserRole, RBAC.Permission.VIEW_AUDIT_LOGS)) {
    showAuditLog();
}

// Enforce permission (throws SecurityException if denied)
// Put this at the start of any sensitive method
RBAC.enforce(currentUserRole, RBAC.Permission.MANAGE_USERS, username);
// Code below only runs if user is ADMIN
deleteUser(userId);
```

### 📋 Audit Logging
```java
import com.security.audit.AuditLogger;

// Log any security event
AuditLogger.log("LOGIN",        "ahmed@hotel.com", "Successful login from 192.168.1.1");
AuditLogger.log("FAILED_LOGIN", "hacker@x.com",   "Wrong password attempt #3");
AuditLogger.log("ACCESS_DENIED","staff@hotel.com","Tried to access admin panel");
AuditLogger.log("DATA_EXPORT",  "admin@hotel.com","Exported guest list (250 records)");

// Convenience methods
AuditLogger.logLogin("ahmed@hotel.com");
AuditLogger.logLogout("ahmed@hotel.com");
AuditLogger.logAdminAction("admin@hotel.com", "Deleted room 301");

// Read logs (newest first)
List<String> all    = AuditLogger.readLogs();
List<String> failed = AuditLogger.readByType("FAILED_LOGIN");
```

### ✅ Input Validation
```java
import com.security.validation.InputValidator;

// Validate before touching the database
String nameError  = InputValidator.validateName("Ahmed Al-Rashidi"); // null = valid
String emailError = InputValidator.validateEmail("not-an-email");    // "Invalid email format."
String dateError  = InputValidator.validateDates(checkIn, checkOut); // null = valid

// Sanitize for display
String safe = InputValidator.sanitize("<script>alert('xss')</script>Hello"); // "Hello"

// See the SQL injection demo (great for presentations!)
InputValidator.sqlInjectionDemo();
```

---

## 🔴 SQL Injection Demo Output

Run `InputValidator.sqlInjectionDemo()` to see this:

```
╔══════════════════════════════════════════════════╗
║         SQL INJECTION DEMONSTRATION             ║
╚══════════════════════════════════════════════════╝
Attack input: ' OR '1'='1'; DROP TABLE users; --

❌ VULNERABLE (string concatenation):
   Query: SELECT * FROM users WHERE username = '' OR '1'='1'; DROP TABLE users; --'
   → Database EXECUTES the injected SQL!
   → Table dropped, authentication bypassed.

✅ PROTECTED (PreparedStatement):
   String sql = "SELECT * FROM users WHERE username = ?";
   stmt = conn.prepareStatement(sql);
   stmt.setString(1, userInput); // driver escapes it
   → Attack string treated as LITERAL DATA. Safe.
```

---

## 🎯 STRIDE Threat Model

Run `StrideModel.printReport()` or see [`docs/STRIDE-threat-model.md`](docs/STRIDE-threat-model.md)

| Category | Threat | Mitigation | Status |
|----------|--------|------------|--------|
| **Spoofing** | Attacker impersonates legitimate user | BCrypt hashing + login lockout | ✅ MITIGATED |
| **Tampering** | Attacker modifies data at rest | AES-256-GCM field encryption | ✅ MITIGATED |
| **Repudiation** | User denies performing an action | Append-only audit log | ✅ MITIGATED |
| **Information Disclosure** | Sensitive data exposed to unauthorized users | PreparedStatements + RBAC + AES | ✅ MITIGATED |
| **Denial of Service** | System flooded with login attempts | IP-based rate limiting | ✅ MITIGATED |
| **Elevation of Privilege** | User gains higher permissions than granted | RBAC enforced on every action | ✅ MITIGATED |

---

## 🧪 Running Tests

```bash
mvn test
```

15 JUnit tests covering:
- BCrypt hash + verify correctness
- AES-256-GCM encrypt/decrypt round-trip
- Random IV (same plaintext → different ciphertext)
- RBAC permission matrix
- Login lockout trigger and reset
- Input validation and sanitization

---

## 📁 Project Structure

```
java-security-toolkit/
├── pom.xml
├── README.md
├── src/
│   ├── main/java/com/security/
│   │   ├── auth/
│   │   │   ├── PasswordManager.java    ← BCrypt hashing
│   │   │   ├── LoginLockout.java       ← Brute force protection
│   │   │   └── SessionManager.java     ← UUID session tokens
│   │   ├── crypto/
│   │   │   └── AESEncryption.java      ← AES-256-GCM encryption
│   │   ├── access/
│   │   │   └── RBAC.java              ← Role-based access control
│   │   ├── audit/
│   │   │   └── AuditLogger.java       ← Append-only audit trail
│   │   ├── validation/
│   │   │   └── InputValidator.java    ← Whitelist validation + SQLi demo
│   │   └── threat/
│   │       └── StrideModel.java       ← STRIDE threat documentation
│   └── test/java/com/security/
│       └── SecurityToolkitTest.java   ← 15 JUnit tests
└── docs/
    ├── STRIDE-threat-model.md
    └── OWASP-checklist.md
```

---

## ⚠️ Production Notes

- **AES Key**: Replace `SECRET_KEY_B64` with `System.getenv("AES_SECRET_KEY")` in production
- **Audit Log**: For high-volume systems, switch `AuditLogger` output to a database table
- **Session Storage**: For web apps, store tokens server-side (Redis/DB), not in-memory
- **BCrypt Cost**: Cost factor 12 is appropriate for 2024+ hardware. Increase to 13-14 for extra security

---

## 📜 License

MIT License — free to use in academic and commercial projects. Attribution appreciated.

---

## 👨‍💻 Author

**Abdullah** — BS Cybersecurity
NuTech, Pakistan

> *"Good OOP design and good security design reinforce each other.  
> Encapsulation prevents data leakage. The DAO pattern makes SQL injection prevention systematic."*
