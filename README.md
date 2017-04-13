# OAuth Filter for Java

This project contains a Servlet Filter that authenticates and authorizes requests using OAuth access tokens of various kinds. There are two `OAuthFilter` implementations. `OAuthJwtFilter` and `OAuthOpaqueFilter`. Both implement `javax.servlet.Filter`, and can be used to protect APIs built using Java. Depending on the format of the access token, these two concrete implementations can be used in the following manner:

1. If the token is a Json Web Token (JWT) then validate the token using a public key
2. If the token is a reference (opaque) token, then validate by calling the OAuth server's
[introspection](https://tools.ietf.org/search/rfc7662) endpoint.

An example of how to use this filter can be found in a [separate repository](https://github.com/curityio/example-java-oauth-protected-api).

## Filter Overview

The filter is build to perform two tasks.

1. Authenticate the caller by validating the incoming access token
2. Authorize the operation by validating the scopes in the access token against the configured scopes

The authorization is very basic, and in the default implementation only checks that all configured scopes are present in the token. A more advanced scenario could check the HTTP method, along with sub-paths in order to determine if the appropriate scope is present in the request. To change the default behavior, override the method `se.curity.oauth.OAuthFilter#authorize`.

## Using Json Web Tokens (JWT)

`OAuthJwtFilter` implements a filter that expects a Json Web Token, and that can validate the token either by using a pre-shared certificate or by calling the OAuth servers Json Web Key (JWK) endpoint. The default is to use the JWK service, as this provides a more maintainable deployment structure for microservices.

## Using Opaque Tokens

`OAuthOpaqueFilter` implements a filter that expects an opaque token (i.e., a token that needs to be introspected in order to determine the contents). This requires the OAuth server to support [introspection](https://tools.ietf.org/search/rfc7662). Introspection means that the API acts as an introspecting client, and, therefore, needs client credentials in order to authenticate itself against the introspection endpoint. Each new token received is introspected, then cached for a limited time. In production, this should be refined to perhaps use a shared cache or at least a datastore for the cache if there is a large number of requests coming in to the API.

## Scope-bases Authorization

The abstract class `OAuthFilter` implements a simple authorize method, that validates the incoming scopes against the configured ones. It is simple to override this method in the implementing classes instead to perform more advanced authorization.

## Configuring the Filter

To configure the filter, the following settings are required for each of the two concrete implementations, depending on the format of the token your OAuth server is using.

### Init-params for the `OAuthJwtFilter`

Configuration Setting Name | Description
---------------------------|----------------
oauthHost                  | Hostname of the OAuth server.
oauthPort                  | Port of the OAuth server.
jsonWebKeysPath            | Path to the JWKS endpoint on the OAuth server.
scope                      | A space separated list of scopes required to access the API.
minKidReloadTimeInSeconds  | Minimum time to reload the webKeys cache used by the Filter.

### Init-params for the `OAuthOpaqueFilter`

Configuration Setting Name | Description
---------------------------|----------------
oauthHost                  | Hostname of the OAuth server.
oauthPort                  | Port of the OAuth server.
introspectionPath          | Path to the introspection endpoint on the OAuth server.
scope                      | A space separated list of scopes required to access the API.
clientId                   | Your application's client id to use for introspection.
clientSecret               | Your application's client secret.

## Providing an external HttpClient

The `OAuthFilter` uses a [HttpClient](https://hc.apache.org/httpcomponents-client-ga/) to communicate with the authentication server. The HttpClient may be overridden by the web application by providing a properties file in the following locations:

* `META-INF/services/OAuthFilter.properties` relative to the classpath
* `OAuthFilter.properties` relative to the working directory

The only accepted property is the name of a supplier class to be used to provide the HttpClient instance:

```properties
openid.httpClientSupplier.className=com.example.HttpClientSupplier
```

(Replace `com.example.HttpClientSupplier` with the name of your own supplier class.)

This class must be an instance of Java 8's `java.util.function.Supplier` interface, and it must provide a `org.apache.http.client.HttpClient`. It also must have a default constructor. See `se.curity.examples.oauth.DefaultJwkHttpClientSupplier` for an example. This will be used if no properties file is found.

## More Information

For more information, please contact [Curity](http://curity.io).

Copyright (C) 2016-2017 Curity AB. All rights reserved
