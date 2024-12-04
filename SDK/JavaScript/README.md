# Auth proxy SDK (JavaScript)
Universal package for authentication process.

## Configuration:

process.env variable are used for configuration:

```
AUTH_API_URL=https://test-project.api/
```

## Usage

### Obtaining a new session

The `signInUserKey` function is used to obtain the cookie:

```ts
var client = new AuthProxyClient();

await client.signInUserKey(`<YOUR_USER_KEY>`);

// Returns sessionId string if session exists
// null if session not found
const sessionId = client.GetSessionId();
```

After that, sessionId can be used to authorize requests.

### Creating or restoring a key

To restore a key, you need to perform the following sequence of requests:

1. Request key restoration
2. Initialize a new key
3. Create a new key

```ts
var client = new AuthProxyClient();

// Sends a code to the email associated with the phone number
// Returns a status string "Success"
// null in case of an error
const result = await client.ResetPassword('<PHONE_NUMBER>');

// Initializes the creation of a new key, sends an OTP code to the associated phone number, and returns data for creating a new key
// null in case of an error
const authOptions = await client.InitializeNewKey('<EMAIL_CODE>');

// Returns the user key, which is set in USER_KEY to obtain sessions
// null in case of an error
const userKey = await client.CreateUserKey('<OTP_CODE>', authOptions);
```
