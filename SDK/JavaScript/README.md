# Auth proxy SDK (JavaScript)
Universal package for authentication process.

## Configuration:

process.env variables are used for configuration:

```
PROJECT_ID=test
AUTH_API_URL=https://test-project.api/
USER_KEY=532be8142c2680590828a64ad46c64bbbe50709de1f23d52cdd69187ad9d62e2
```

## Usage

### Obtaining a new session

The `signInUserKey` function is used to obtain the cookie:

```ts
// Returns a string containing the session ID
// null in case of an error
const sessionId = await signInUserKey();
```

After that, sessionId can be used to authorize requests.

### Creating or restoring a key

To restore a key, you need to perform the following sequence of requests:

1. Request key restoration
2. Initialize a new key
3. Create a new key

```ts
// Sends a code to the email associated with the phone number
// Returns a status string "Success"
// null in case of an error
const result = await resetPassword('<PHONE_NUMBER>');

// Initializes the creation of a new key, sends an OTP code to the associated phone number, and returns data for creating a new key
// null in case of an error
const authOptions = await initializeNewKey({ code: '<EMAIL_CODE>' });

// Returns the user key, which is set in USER_KEY to obtain sessions
// null in case of an error
const userKey = await createUserKey('<OTP_CODE>', authOptions);
```
