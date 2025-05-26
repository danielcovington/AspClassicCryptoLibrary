
# CryptoLibrary — COM‑Visible Encryption & Password Hashing DLL  
*(C# 7.3 / .NET Framework 4.x compatible, Classic ASP‑ready)*

---

## 1  Overview
`CryptoLibrary` exposes a single COM‑visible class **`CryptoManager`** that gives legacy
VBScript/Classic ASP applications modern cryptography with two, clearly separated use‑cases:

| Feature | API | Algorithm | Reversible? |
|---------|-----|-----------|-------------|
| Symmetric encryption | `Encrypt`, `Decrypt` | AES‑256 (CBC) + HMAC‑SHA‑256 | **Yes** |
| One‑way password hashing | `HashPassword`, `VerifyPassword` | PBKDF2‑SHA‑512 (150‑k iterations) | **No** |

All methods raise COM exceptions, so Classic ASP can trap errors (`Err.Number`, `Err.Description`) without crashing the worker process.

---

## 2  Building the DLL

1. **Add `CryptoManager.cs`** to a new **Class Library** targeting **.NET Framework 4.8**.  
2. Ensure assembly‑wide visibility is turned on:  

   ```csharp
   [assembly: ComVisible(true)]
   ```
3. Project ▸ **Properties ▸ Build ▸** tick **“Register for COM interop”** if compiling on the target machine.  
4. Build **Release**.

> Building on CI? Un‑tick the checkbox and register manually on the server (see below).

---

## 3  Registering on the IIS server

```bat
rem Run from an elevated “Developer Command Prompt for VS”
regasm CryptoLibrary.dll /codebase /tlb
```

* `/codebase` — lets COM locate the DLL outside the GAC  
* `/tlb` — generates a type library Classic ASP understands  
* To uninstall: `regasm CryptoLibrary.dll /unregister`

---

## 4  Method Reference

| Method | Parameters | Returns | Notes |
|--------|------------|---------|-------|
| `Encrypt(plainText, secret)` | `plainText` *(string)*, `secret` *(string)* | Base‑64 `SALT|IV|CIPHER|HMAC` | Use same *secret* for `Decrypt`. |
| `Decrypt(cipherPackage, secret)` | `cipherPackage` *(Base‑64)*, `secret` *(string)* | Original plaintext | Throws if key is wrong or data modified. |
| `HashPassword(password)` | `password` *(string)* | Base‑64 `SALT|HASH` | Cannot be reversed. |
| `VerifyPassword(password, storedHash)` | `password` *(string)*, `storedHash` *(string)* | `True` / `False` | Constant‑time compare. |

---

## 5  Classic ASP Usage Example

```asp
<%
Dim crypto : Set crypto = Server.CreateObject("CryptoLibrary.CryptoManager")

Const secret = "CorrectHorseBatteryStaple"
Dim plain   : plain = "super‑secret‑password"

' Encryption round‑trip
Dim cipher : cipher = crypto.Encrypt(plain, secret)
Response.Write "Cipher: " & cipher & "<br>"
Response.Write "Back:   " & crypto.Decrypt(cipher, secret) & "<br>"

' Password hashing
Dim stored : stored = crypto.HashPassword(plain)
If crypto.VerifyPassword(plain, stored) Then
  Response.Write "Password verified!"
Else
  Response.Write "Invalid password!"
End If
%>
```

### Error‑handling pattern

```asp
On Error Resume Next
cipher = crypto.Encrypt("data", "key")

If Err.Number <> 0 Then
  Response.Write "Crypto error " & Err.Number & ": " & Err.Description
  Err.Clear
End If
```

---

## 6  Encryption **vs.** Hashing — when to use which?

| Question | Choose |
|----------|--------|
| **Do you need the original value back later?** | **Yes → `Encrypt` / `Decrypt`**<br>**No → `HashPassword` / `VerifyPassword`** |

| Use‑case | Recommended API | Why |
|----------|-----------------|-----|
| Storing user login passwords | `HashPassword` | One‑way storage prevents leaks. |
| Refresh tokens / PII in DB | `Encrypt` | App must decrypt at runtime. |
| “Remember me” cookie value | `Encrypt` | Server needs the clear text. |
| Document integrity proof | `HashPassword` | Only need to check equality. |

#### Security implications
* **Encryption**: protect the **key**; if it leaks, all ciphertexts become readable.  
* **Hashing**: salts + thousands of PBKDF2 iterations slow brute‑force attacks even after a DB breach.

---

## 7  Performance Notes
* **HashPassword / VerifyPassword** run ~100 ms on typical 2025 hardware (150 000 iterations).  
* **Encrypt / Decrypt** are ~100× faster; use for per‑row data protection.

---

## 8  Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ActiveX component can't create object` | DLL not registered, or x86/x64 mismatch. Register with 64‑bit *regasm* if app‑pool is 64‑bit. |
| Compilation error: `RandomNumberGenerator.Fill` missing | You’re on .NET Framework 4.x — use the RNGCryptoServiceProvider version (already in the C# 7.3 file). |
| `CryptographicException: HMAC mismatch` | Wrong pass‑phrase or data corrupted. |

---

## 9  Updating

1. Stop or recycle the IIS app‑pool.  
2. Replace `CryptoLibrary.dll`.  
3. `regasm CryptoLibrary.dll /codebase /tlb` again.  
4. Start the app‑pool.

---

© 2025 CryptoLibrary example code. Provided under MIT license.  

