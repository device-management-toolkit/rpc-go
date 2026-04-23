# 🚨 Breaking Change Release — v3.0.0

## 🔑 Breaking Changes

### 1. Explicit flag syntax

* **Long-form flags** must now use `--` (e.g., `--profile`).
* **Short-form flags** must now use `-` (e.g., `-p`).

---

### 2. `config` now means “application configuration”

* `config` now refers to the **application’s own configuration** (Go-standard).
* `configv2` has been **removed**.

---

### 3. Old `config` → now called `profile`

* The concept of `config` used for provisioning (previously passed as `configv2`) is now called a **profile**.
* Use the `--profile` flag to provide this, aligning with the rest of the device-management-toolkit.

---

## 🚀 Migration Examples

### Example: Switching from `configv2` to `--profile`

**Before (v2.x):**

```bash
rpc-go configure --configv2 path/to/profile.yaml
```

**After (v3.0):**

```bash
rpc-go configure --profile path/to/profile.yaml
# or, where supported:
rpc-go configure -p path/to/profile.yaml
```



## ✅ Summary

* **Flags must be explicit** (`--long`, `-s`).
* **`config` = app configuration**.
* **`configv2` removed**.
* **`--profile` replaces `configv2`**.

---

