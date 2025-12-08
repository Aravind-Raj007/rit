# CyberGuard Lite - Authentication API Documentation

## Overview

The CyberGuard Lite authentication system is **100% local** - user accounts are stored in SQLite with bcrypt-hashed passwords. No cloud, no internet, no external authentication services.

---

## Authentication Methods

All methods are accessible via `window.electronAPI` in React components.

### Registration

#### `register(username, password)`

Register a new user account.

**Parameters:**

- `username` (string) - Username (3-30 characters, alphanumeric + underscore)
- `password` (string) - Password (minimum 12 characters)

**Validation:**

- Username must be unique
- Username: 3-30 characters, letters/numbers/underscores only
- Password: minimum 12 characters

**Returns:**

```javascript
{
  success: true,
  message: 'Registration successful',
  userId: 1
}
```

**Example:**

```javascript
const handleRegister = async (username, password) => {
  const result = await window.electronAPI.register(username, password);

  if (result.success) {
    console.log("User registered:", result.userId);
    // Redirect to login or auto-login
  } else {
    console.error("Registration failed:", result.message);
    // Show error to user
  }
};
```

---

### Login

#### `login(username, password)`

Login with username and password.

**Parameters:**

- `username` (string) - Username
- `password` (string) - Password

**Returns:**

```javascript
{
  success: true,
  userId: 1,
  username: 'john_doe',
  message: 'Login successful'
}
```

**Error Responses:**

- User not found: `{ success: false, message: 'User not found' }`
- Wrong password: `{ success: false, message: 'Wrong password' }`

**Example:**

```javascript
const handleLogin = async (username, password) => {
  const result = await window.electronAPI.login(username, password);

  if (result.success) {
    console.log("Logged in as:", result.username);
    // Store userId in React state/context
    // Redirect to dashboard
  } else {
    console.error("Login failed:", result.message);
    // Show error message
  }
};
```

---

### Session Management

#### `getCurrentUser()`

Get currently logged-in user.

**Returns:**

```javascript
{
  userId: 1,
  username: 'john_doe'
}
// or null if not logged in
```

**Example:**

```javascript
const checkAuth = async () => {
  const user = await window.electronAPI.getCurrentUser();

  if (user) {
    console.log("Current user:", user.username);
  } else {
    console.log("Not logged in");
    // Redirect to login page
  }
};
```

---

#### `isLoggedIn()`

Check if user is logged in.

**Returns:**

```javascript
true; // if logged in
false; // if not logged in
```

**Example:**

```javascript
const ProtectedRoute = ({ children }) => {
  const [isAuth, setIsAuth] = useState(false);

  useEffect(() => {
    async function checkAuth() {
      const loggedIn = await window.electronAPI.isLoggedIn();
      setIsAuth(loggedIn);
    }
    checkAuth();
  }, []);

  if (!isAuth) {
    return <Navigate to="/login" />;
  }

  return children;
};
```

---

#### `logout()`

Logout current user.

**Returns:**

```javascript
{
  success: true,
  message: 'Logged out'
}
```

**Example:**

```javascript
const handleLogout = async () => {
  const result = await window.electronAPI.logout();

  if (result.success) {
    console.log("Logged out successfully");
    // Clear React state
    // Redirect to login page
  }
};
```

---

### Validation

#### `validateUsername(username)`

Validate username before registration.

**Parameters:**

- `username` (string) - Username to validate

**Returns:**

```javascript
{
  valid: true,
  message: 'Username is available'
}
// or
{
  valid: false,
  message: 'Username already taken'
}
```

**Validation Rules:**

- Not empty
- 3-30 characters
- Alphanumeric + underscore only
- Must be unique

**Example:**

```javascript
const checkUsername = async (username) => {
  const result = await window.electronAPI.validateUsername(username);

  if (result.valid) {
    setUsernameError("");
    setUsernameAvailable(true);
  } else {
    setUsernameError(result.message);
    setUsernameAvailable(false);
  }
};
```

---

#### `validatePassword(password)`

Validate password and check strength.

**Parameters:**

- `password` (string) - Password to validate

**Returns:**

```javascript
{
  valid: true,
  message: 'Password is valid',
  strength: 'strong'  // 'weak', 'medium', or 'strong'
}
```

**Strength Calculation:**

- **Weak**: < 12 characters or low variety
- **Medium**: 12+ characters with some variety
- **Strong**: 16+ characters with uppercase, lowercase, numbers, and special characters

**Example:**

```javascript
const checkPassword = async (password) => {
  const result = await window.electronAPI.validatePassword(password);

  if (result.valid) {
    setPasswordStrength(result.strength);
    setPasswordError("");
  } else {
    setPasswordError(result.message);
  }
};
```

---

### Password Management

#### `changePassword(oldPassword, newPassword)`

Change password for current user.

**Parameters:**

- `oldPassword` (string) - Current password
- `newPassword` (string) - New password (minimum 12 characters)

**Returns:**

```javascript
{
  success: true,
  message: 'Password changed successfully'
}
```

**Example:**

```javascript
const handleChangePassword = async (oldPass, newPass) => {
  const result = await window.electronAPI.changePassword(oldPass, newPass);

  if (result.success) {
    console.log("Password changed");
    // Show success message
  } else {
    console.error("Error:", result.message);
  }
};
```

---

### Statistics

#### `getUserStats(userId)`

Get user statistics.

**Parameters:**

- `userId` (number) - User ID

**Returns:**

```javascript
{
  success: true,
  stats: {
    encryptedFiles: 5,
    totalScans: 23,
    networkDevices: 8,
    activeTasks: 3,
    activityLogs: 150
  }
}
```

---

## Complete Registration Example

```javascript
import { useState } from "react";

function RegisterPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [passwordStrength, setPasswordStrength] = useState("");

  const handleUsernameChange = async (e) => {
    const value = e.target.value;
    setUsername(value);

    if (value.length >= 3) {
      const result = await window.electronAPI.validateUsername(value);
      setUsernameError(result.valid ? "" : result.message);
    }
  };

  const handlePasswordChange = async (e) => {
    const value = e.target.value;
    setPassword(value);

    const result = await window.electronAPI.validatePassword(value);
    setPasswordError(result.valid ? "" : result.message);
    setPasswordStrength(result.strength);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const result = await window.electronAPI.register(username, password);

    if (result.success) {
      alert("Registration successful!");
      // Auto-login or redirect to login page
      const loginResult = await window.electronAPI.login(username, password);
      if (loginResult.success) {
        // Redirect to dashboard
        window.location.href = "/dashboard";
      }
    } else {
      alert("Registration failed: " + result.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div>
        <label>Username</label>
        <input
          type="text"
          value={username}
          onChange={handleUsernameChange}
          required
        />
        {usernameError && <p className="error">{usernameError}</p>}
      </div>

      <div>
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={handlePasswordChange}
          required
        />
        {passwordError && <p className="error">{passwordError}</p>}
        {passwordStrength && (
          <p className={`strength-${passwordStrength}`}>
            Strength: {passwordStrength}
          </p>
        )}
      </div>

      <button type="submit">Register</button>
    </form>
  );
}
```

---

## Complete Login Example

```javascript
import { useState } from "react";
import { useNavigate } from "react-router-dom";

function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const result = await window.electronAPI.login(username, password);

    if (result.success) {
      // Store user info in context/state
      localStorage.setItem("userId", result.userId);
      localStorage.setItem("username", result.username);

      // Redirect to dashboard
      navigate("/dashboard");
    } else {
      setError(result.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h1>Login to CyberGuard Lite</h1>

      {error && <div className="error">{error}</div>}

      <div>
        <label>Username</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </div>

      <div>
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>

      <button type="submit">Login</button>

      <p>
        Don't have an account? <a href="/register">Register</a>
      </p>
    </form>
  );
}
```

---

## Security Features

✅ **Bcrypt Password Hashing** - Cost factor: 10  
✅ **Password Strength Validation** - Minimum 12 characters  
✅ **Username Uniqueness** - Checked before registration  
✅ **Session in Memory** - No cookies, no localStorage for session  
✅ **Activity Logging** - All auth actions logged  
✅ **Local-only** - No internet, no cloud

---

## Session Storage

**Important:** The session is stored in memory in the Electron main process, NOT in the browser. This means:

- Session persists only while app is running
- Closing the app logs out the user
- No session cookies or tokens
- More secure than browser-based sessions

---

## Error Messages

| Error                                          | Meaning                     |
| ---------------------------------------------- | --------------------------- |
| `Username cannot be empty`                     | Username field is empty     |
| `Username must be at least 3 characters`       | Username too short          |
| `Username already taken`                       | Username exists in database |
| `Password must be at least 12 characters long` | Password too short          |
| `User not found`                               | Username doesn't exist      |
| `Wrong password`                               | Password doesn't match      |
| `Not logged in`                                | User must login first       |

---

## Best Practices

1. **Always validate before submitting** - Use `validateUsername()` and `validatePassword()` as user types
2. **Show password strength** - Display strength indicator to encourage strong passwords
3. **Handle errors gracefully** - Show user-friendly error messages
4. **Auto-login after registration** - Better UX
5. **Protect routes** - Check `isLoggedIn()` before rendering protected pages
6. **Clear sensitive data** - Don't store passwords in React state longer than necessary
7. **Log activity** - Authentication events are automatically logged
