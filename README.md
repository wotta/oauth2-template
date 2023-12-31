# Github Provider for OAuth 2.0 Client
[![Latest Version](https://img.shields.io/github/release/wotta/oauth2-template.svg?style=flat-square)](https://github.com/wotta/oauth2-template/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/wotta/oauth2-template/master.svg?style=flat-square)](https://travis-ci.org/wotta/oauth2-template)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/wotta/oauth2-template.svg?style=flat-square)](https://scrutinizer-ci.com/g/wotta/oauth2-template/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/wotta/oauth2-template.svg?style=flat-square)](https://scrutinizer-ci.com/g/wotta/oauth2-template)
[![Total Downloads](https://img.shields.io/packagist/dt/wotta/oauth2-template.svg?style=flat-square)](https://packagist.org/packages/wotta/oauth2-template)

This package provides Custom Provider OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## How to use

In order to correctly use this template repository you will need to go through the code and update all references from `Custom` to `YourProvider`. This is not meant to be installed as a standalone package.

This is merely being provided as a basic starter point since there was no easy to use one yet.
In the future additions will be added to make it even more simple.

## Installation

To install, use composer:

```
composer require league/oauth2-template
```

## Usage

Usage is the same as The League's OAuth client, using `\Wotta\OAuth2\Client\Provider\CustomProvider` as the provider.

### Authorization Code Flow

```php
$provider = new League\OAuth2\Client\Provider\CustomProvider([
    'clientId'          => '{provider-client-id}',
    'clientSecret'      => '{provider-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url',
]);

if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the user's details
        $user = $provider->getResourceOwner($token);

        // Use these details to create a new profile
        printf('Hello %s!', $user->getNickname());

    } catch (Exception $e) {

        // Failed to get user details
        exit('Oh dear...');
    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();
}
```

### Managing Scopes

When creating your provider's authorization URL, you can specify the state and scopes your application may authorize.

```php
$options = [
    'state' => 'OPTIONAL_CUSTOM_CONFIGURED_STATE',
    'scope' => ['add','custom:scope','here'] // array or string;
];

$authorizationUrl = $provider->getAuthorizationUrl($options);
```
If neither are defined, the provider will utilize internal defaults.

At the time of authoring this documentation, the [following scopes are available](https://custom.provider.com/v3/oauth/#scopes).

- add
- custom:scope
- here

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/wotta/oauth2-template/blob/master/CONTRIBUTING.md) for details.


## Credits

- [Wouter van Marrum](https://github.com/wotta)
- [All Contributors](https://github.com/wotta/oauth2-template/contributors)


## License

The MIT License (MIT). Please see [License File](https://github.com/wotta/oauth2-template/blob/master/LICENSE) for more information.