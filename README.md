# AuthKit

This is a MoopsyJS kit! A lightweight package that can hook into your Moopsy flows but is not technically-exclusive to Moopsy. This kit **depends on MongoDB**.

AuthKit handles password-based authentication and the saving of login tokens. You can integrate it into your Moopsy app as so:

### 1. [Server] Install

In your `backend/`:

```
npm i --save @moopsyjs/kit-auth
```

In your **project root** (so types are accessible in `common/`):

```
npm i --save-dev @moopsyjs/kit-auth
```

### 2. [Server] Define an authKit singleton

```backend/src/singletons/auth.ts
import { AuthKit } from "@moopsyjs/kit-auth";
import { mongoDB } from "./mongo";

export const authKit = new AuthKit(mongoDB);
```


### 3. [Common] Create/update your auth spec

This should be in `common/` as you'll need it on the frontend and the backend:

```common/src/types/auth/auth-spec.ts
export interface AuthSpec {
    PublicAuthType: { uuid: string; }; // <- you can have whatever you want here
    AuthRequestType: { plainToken: string; };
}
```

### 4. [Server] Update your MoopyServer
```backend/src/singletons/moopsy-server.ts
import { authKit } from "./auth";

type PrivateAuthType = AuthSpec["PublicAuthType"]; // <- Here we say that auth.private and auth.public are the same, but you don't have to do this

function handleAuthLogin(params: AuthSpec["AuthRequestType"]): MoopsySuccessfulAuthResponsePackage<AuthSpec["PublicAuthType"], PrivateAuthType> {
    const { userId } = authKit.checkLoginToken({ token: params.plainToken });

    // Do whatever logic you want here to get whatever you want public and private auth type to be

    return {
        public: { uuid: userId },
        private: { uuid: userId },
    }
}

export const server = new MoopsyServer<
  AuthSpec,
  PrivateAuthType
>(
  {
    verbose: false,
    port: 3001,
  },
  {
    handleAuthLogin
  }
);

```

### 5. [Server] Create a login method

This method will accept credentials and return a token. Let's create the blueprint:

```common/src/blueprints/auth/login.ts
import type { AuthKitHashedString } from "@moopsyjs/kit-auth";

export type ParamsType = {
    email: string;
    password: AuthKitHashedString;
};
export type ResponseType = {
    plainToken: string;
};
export const Endpoint = "auth/login";
export const Method = "POST";

export interface Plug {
    params: ParamsType;
    response: ResponseType;
    method: typeof Method;
    endpoint: typeof Endpoint;
}

export const RateLimitingConfig = {
    calls: 1,
    per: 2000,
};
```

Setup the handler:

```backend/src/api/endpoints/auth/login.ts
import * as BP from "../../../blueprints/auth/login";
import { server } from '../../../singletons/moopsy-server';

server.endpoints.register<BP.Plug>(BP, async (params) => {
    const userId = myCustomLoginToGetTheUserIdFromEmail(params.email); // <- insert your own logic

    const { plainToken } = await authKit.loginUserWithUserIdAndPassword({ userId, password: params.password });

    return { plainToken };
});
```

### 6. [Client] Configure MoopsyClientAuthExtension

Use the same AuthSpec to configure the auth extension

```frontend/src/singletons/auth.ts
import { MoopsyClientAuthExtension } from "@moopsyjs/react";

import { client } from "./moopsy-client";
import { AuthSpec } from '../types/users/auth-spec';

export const authExtension = new MoopsyClientAuthExtension<AuthSpec>(
  client, // <- Your moopsy client
  {
    autoLoginFunction: async (): Promise<AuthSpec["AuthRequestType"] | null> => { // <- Auto login function will automatically attempt to login your user when a connection is established
      const plainToken = window.localStorage.loginToken; // <- Retrieve the token from local storage

      if (plainToken != null) {
        return {
          plainToken // <- Pass it back
        };
      }

      return null;
    },
  },
);
```

### 7. [Client] Login the user and save the token

```frontend/src/.../login.tsx
...

async function hashString (plaintext: string): Promise<{ algorithm: string; digest: string; }> {
  return {
    digest: Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', (new TextEncoder()).encode(plaintext)))).map(b => b.toString(16).padStart(2, '0')).join(''), // <- Simple hex SHA256 digest, feel free to replace with your own
    algorithm: 'sha-256'
  };
}

const loginMutation = client.useMutation<LoginBP.Plug>(LoginBP);

const login = React.useCallback(async () => {
    const hashedPassword = await hashString(password);

    loginMutation.call({ email, password: hashedPassword }) // <- remember this is pseudo-y code, you'll need to get email and password somehow from your form
      .then(res => {
        window.localStorage.loginToken = res.plainToken; // <- Save the login token
        await authExtension.login({ plainToken: res.plainToken }); // <- Call login() directly on authExtension (autoLoginFunction will cover future page loads)
        // ^ remember to handle any errors
      })
      .catch(err => {
        alert(err.message);
      });
}, []); // <- [pseudo warning] probably don't want this to be empty

...
```

And that's it! The user is now logged in. This is definitely a lot more complex than some other frameworks, but we feel it is needed to allow for maximum flexibility.
Moopsy's auth system allows use to use any system you want for authenticating, like SSO, OAuth, etc.

## Improvements

The MoopsyJS team is working on further improvements, both by improving the authentication system of MoopsyJS and by improving this kit. We're also looking to release a client side library to make things easy as well.

## Further Work

Beyond this tutorial, some considerations to make:

1. When the user requests to logout, you'll want to create an endpoint that calls `authKit.dropToken()` (+ any other things you want to do)
2. AuthKit defaults specify 24 bytes for a login token length and 365 days for the expiry. Tweak these as needed for your use case
3. You'll need to implement handling for when a token expires/invalidates, you can use `authExtension.onAutoLoginFailure()` to hook into failures, but remember failures could be caused by something as simple as a network issue or server outage. AuthKit throws a 404-coded error when a login token is invalid, so this should be the only case you treat as a login token expiration/invalidation
4. Our tutorial has you saving your login token in localStorage, but you may want to use an alternative storage system like sessionStorage or IndexedDB