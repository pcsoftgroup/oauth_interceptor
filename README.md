# OAuth Interceptor

Oven-ready [Dio](https://pub.dev/packages/dio) interceptor for handling OAuth 2.0.

## Features

- Easily request authentication tokens using OAuth 2.0 grants
- Add an interceptor to your Dio instance which adds the Bearer token to every request
- Stores tokens using [Flutter Secure Storage](https://pub.dev/packages/flutter_secure_storage)
- Automatically refreshes expired tokens

## Installation

![Pub Version](https://img.shields.io/pub/v/oauth_interceptor)

```bash
flutter pub add oauth_interceptor
```

## Usage

### Step 1: Create an `OAuth` instance

```dart
final oAuth = OAuth(
    tokenUrl: 'oauth/token',
    clientId: '1',
    clientSecret: 'secret',
    dio: myBaseDio, // Optional; if ommitted OAuth will use a basic Dio instance
    name: 'client', // Required if you have multiple instances of OAuth e.g. for storing client and password tokens separately
);
```

### Step 2: Add the `OAuth` instance as a Dio interceptor

```dart
final authenticatedDio = Dio()..interceptors.add(oAuth);
```

### Step 3: Use the login/logout methods

```dart
final isSignedIn = await oAuth.isSignedIn; // Will be true if a token exists in storage

oAuth.login(const ClientCredentialsGrant());
oAuth.login(
    PasswordGrant(username: 'me@example.com', password: 'password'),
);

oAuth.logout();

oAuth.refresh(); // This should happen automatically if a token has expired, but you can also manually refresh tokens if you like.
```

### Creating your own grant type

The packages exposes an `OAuthGrantType` abstract class which can be implemented, allowing you to create your own custom grant types.

```dart
class CustomGrantType implements OAuthGrantType {
    @override
    FutureOr<RequestOptions> handle(RequestOptions request) async {
        // Do something fancy with the request
        return request;
    }
}
```

### Interceptor flowchart

![Flow chart showing interceptor logic](documentation/request_flow.drawio.svg)
