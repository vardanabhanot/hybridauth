<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2017 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

/**
 * X OAuth2 provider adapter.
 *
 * Example:
 *
 *   $config = [
 *       'callback' => Hybridauth\HttpClient\Util::getCurrentUrl(),
 *       'keys' => ['id' => '', 'secret' => ''],
 *   ];
 *
 *   $adapter = new Hybridauth\Provider\X($config);
 *
 *   try {
 *       $adapter->authenticate();
 *
 *       $userProfile = $adapter->getUserProfile();
 *       $tokens = $adapter->getAccessToken();
 *   } catch (\Exception $e) {
 *       echo $e->getMessage() ;
 *   }
 */
class X extends OAuth2
{
    /**
     * {@inheritdoc}
     */
    // phpcs:ignore
    protected $scope = 'users.read users.email tweet.read offline.access';

    /**
     * {@inheritdoc}
     */
    protected $apiBaseUrl = 'https://api.twitter.com/2/';

    /**
     * {@inheritdoc}
     */
    protected $authorizeUrl = 'https://x.com/i/oauth2/authorize';

    /**
     * {@inheritdoc}
     */
    protected $accessTokenUrl = 'https://api.x.com/2/oauth2/token';

    /**
     * {@inheritdoc}
     */
    protected $apiDocumentation = 'https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code';

    /**
     * {@inheritdoc}
     */
    protected function initialize()
    {
        parent::initialize();

        // Generating PKCE challange code and challenge verifier
        // https://datatracker.ietf.org/doc/html/rfc7636
        $challenge_verifier = random_bytes(96);

        // We need URL safe base64
        $challenge_verifier = rtrim(strtr(base64_encode($challenge_verifier), '+/', '-_'), '=');
        $code_challenge = hash('sha256', $challenge_verifier, true);
        $code_challenge = rtrim(strtr(base64_encode($code_challenge), '+/', '-_'), '=');

        $this->AuthorizeUrlParameters += [
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256',
        ];

        $stored_code_verifier = $this->getStoredData('challenge_verifier');
        if(!empty($stored_code_verifier)){
            $this->tokenExchangeParameters += [
                'code_verifier' => $stored_code_verifier,
            ];

            $this->tokenExchangeHeaders += [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => 'Basic '. base64_encode($this->clientId.':'.$this->clientSecret),
            ];
        }

        $this->storeData('challenge_verifier', $challenge_verifier);
    }

    /**
     * {@inheritdoc}
     *
     * See: https://docs.x.com/x-api/users/user-lookup-me
     */
    public function getUserProfile()
    {
        $fields = [
            'id',
            'name',
            'username',
            'url',
            'location',
            'confirmed_email',
            'profile_image_url'
        ];

        // Note that en_US is needed for gender fields to match convention.
        $response = $this->apiRequest('users/me', 'GET', [
            'user.fields' => implode(',', $fields),
        ]);

        $data = new Data\Collection($response);

        if (!$data->exists('id')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();

        $userProfile->identifier = $data->get('id');
        $userProfile->firstName = $data->get('username');
        $userProfile->displayName = $data->get('name');
        $userProfile->photoURL = $data->get('profile_image_url');
        $userProfile->webSiteURL = $data->get('url');
        $userProfile->email = $data->get('confirmed_email');
        $userProfile->emailVerified = $data->get('confirmed_email');
        $userProfile->region = $data->get('location');

        if ($this->config->get('photo_size')) {
            $userProfile->photoURL .= '?sz=' . $this->config->get('photo_size');
        }

        return $userProfile;
    }
}
