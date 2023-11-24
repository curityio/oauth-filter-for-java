# OAuth Filter for Java

[![Quality](https://img.shields.io/badge/quality-test-yellow)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

This project contains a Servlet Filter that authenticates and authorizes requests using OAuth access tokens of various kinds. There are two `OAuthFilter` implementations. `OAuthJwtFilter` and `OAuthOpaqueFilter`. Both implement `jakarta.servlet.Filter`, and can be used to protect APIs built using Java. Depending on the format of the access token, these two concrete implementations can be used in the following manner:

1. If the token is a Json Web Token (JWT) then validate the token using a public key
2. If the token is a reference (opaque) token, then validate by calling the OAuth server's
[introspection](https://tools.ietf.org/search/rfc7662) endpoint.

An example of how to use this filter can be found in a [separate repository](https://github.com/curityio/example-java-oauth-protected-api).

## Filter Overview

The filter is build to perform two tasks.

1. Authenticate the caller by validating the incoming access token
2. Authorize the operation by validating the scopes in the access token against the configured scopes

The authorization is very basic, and in the default implementation only checks that all configured scopes are present in the token. A more advanced scenario could check the HTTP method, along with sub-paths in order to determine if the appropriate scope is present in the request. To change the default behavior, override the method `io.curity.oauth.OAuthFilter#authorize`.

## Using Json Web Tokens (JWT)

`OAuthJwtFilter` implements a filter that expects a Json Web Token, and that can validate the token either by using a pre-shared certificate or by calling the OAuth servers Json Web Key (JWK) endpoint. The default is to use the JWK service, as this provides a more maintainable deployment structure for microservices.

## Using Opaque Tokens

`OAuthOpaqueFilter` implements a filter that expects an opaque token (i.e., a token that needs to be introspected in order to determine the contents). This requires the OAuth server to support [introspection](https://tools.ietf.org/search/rfc7662). Introspection means that the API acts as an introspecting client, and, therefore, needs client credentials in order to authenticate itself against the introspection endpoint. Each new token received is introspected, then cached for a limited time. In production, this should be refined to perhaps use a shared cache or at least a datastore for the cache if there is a large number of requests coming in to the API.

## Scope-bases Authorization

The abstract class `OAuthFilter` implements a simple authorize method, that validates the incoming scopes against the configured ones. It is simple to override this method in the implementing classes instead to perform more advanced authorization.

## Installing the library

The `oauth-filter` library is available on Maven Central since version 3.0.0. so you can easily include in your projects.

For example, if you use Maven, add to your `pom.xml`:

```xml
<dependency>
    <groupId>io.curity</groupId>
    <artifactId>oauth-filter</artifactId>
    <version>3.0.0</version>
</dependency>
```

or with Gradle, inlcude in `build.gradle`:

```groovy
implementation 'io.curity:oauth-filter:3.0.0'
```

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

The `OAuthFilter` uses an [HttpClient](https://hc.apache.org/httpcomponents-client-ga/) to communicate with the authentication server. The HttpClient may be overridden by the web application by defining a service Provider class in this location:

* `META-INF/services/io.curity.oauth.HttpClientProvider` relative to the classpath

The file should contain the name of the class used as the provider, e.g. `com.example.HttpClientProvider`

This class must extend the abstract class `io.curity.oauth.HttpClientProvider` and implement two methods which create an introspection client (implementation of `io.curity.oauth.IntrospectionClient`), and a web keys client (implementation of `io.curity.oauth.WebKeysClient`).

## More Information

For more information, please contact [Curity](http://curity.io).

Copyright (C) 2016-2017 Curity AB. All rights reserved
