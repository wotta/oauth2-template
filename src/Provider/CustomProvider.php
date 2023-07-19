<?php

namespace Wotta\Oauth2\Client\Provider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\CustomIdentityProviderException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class CustomProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Domain
     *
     * @var string
     */
    public $domain = 'https://example.com';

    /**
     * Api domain
     *
     * @var string
     */
    public $apiDomain = 'https://api.example.com';

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->domain . '/login/oauth/authorize';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->domain . '/login/oauth/access_token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        if ($this->domain === 'https://github.com') {
            return $this->apiDomain . '/user';
        }
        return $this->domain . '/api/v3/user';
    }

    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $response = parent::fetchResourceOwnerDetails($token);

        if (empty($response['email'])) {
            $url = $this->getResourceOwnerDetailsUrl($token) . '/emails';

            $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);

            $responseEmail = $this->getParsedResponse($request);

            $response['email'] = isset($responseEmail[0]['email']) ? $responseEmail[0]['email'] : null;
        }

        return $response;
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [
            'user.email',
        ];
    }

    /**
     * Check a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array             $data     Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw CustomIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw CustomIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param  array       $response
     * @param  AccessToken $token
     * @return \League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new CustomResourceOwner($response);
    }
}