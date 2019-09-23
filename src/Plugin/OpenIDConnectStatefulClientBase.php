<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\openid_connect\OpenIDConnectAuthmap;
use Drupal\user\UserInterface;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Form\FormStateInterface;

/**
 * Base class for stateful OpenID Connect client plugins.
 *
 * In order to retain method signature compatibility with
 * OpenIDConnectClientInterface, for the time being some methods will
 * accept arguments that are intended to be discarded.
 *
 * @see OpenIDConnectStatefulClientBase
 * @see OpenIDConnectStalessClientWrapper
 * @see OpenIDConnect::completeAuthorization()
 * @see OpenIDConnect::connectCurrentUser()
 * @see OpenIDConnectClientInterface
 * @see OpenIDConnectClientBase
 */
abstract class OpenIDConnectStatefulClientBase extends OpenIDConnectClientBase implements OpenIDConnectStatefulClientInterface {

  /**
   * The logger channel for this plugin.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * The minimum set of scopes for this client.
   *
   * @var array|null
   *
   * @see \Drupal\openid_connect\OpenIDConnectClaims::getScopes()
   */
  protected $clientScopes = NULL;

  /**
   * The authorization code.
   *
   * @var string
   */
  protected $code;

  /**
   * Tokens as retrieved from the Token endpoint.
   *
   * @var array
   *
   * @see OpenIdConnectStatefulClientInterface::retrieveTokens()
   */
  protected $tokens;

  /**
   * Access Token as retrieved from the Token endpoint.
   *
   * @var string
   */
  protected $accessToken;

  /**
   * The undecoded ID Token as retrieved from the Token endpoint.
   *
   * @var string
   */
  protected $originalIdToken;

  /**
   * The decoded ID Token.
   *
   * @var array
   *
   * @see OpenIDConnectStatefulClientInterface::validateIDToken()
   * @see OpenIDConnectStatefulClientInterface::getDecodedIdToken()
   */
  protected $idToken;

  /**
   * The original sub.
   *
   * @var string
   *
   * @see OpenIDConnectStatefulClientInterface::validateSub()
   * @see OpenIDConnectStatefulClientInterface::getSub()
   */
  protected $originalSub;

  /**
   * Possibly modified sub.
   *
   * @var string
   *
   * @see OpenIDConnectStatefulClientBase::getNormalizedSub()
   */
  protected $sub;

  /**
   * UserInfo before possible changes by hook_openid_connect_userinfo_alter().
   *
   * @var array
   *
   * @see OpenIDConnectStatefulClientInterface::updateUserInfo()
   * @see hook_openid_connect_userinfo_alter()
   */
  protected $originalUserInfo;

  /**
   * The UserInfo, from UserInfo endpoint or as part of ID Token.
   *
   * May have been changed by hook_openid_connect_userinfo_alter().
   *
   * @var array
   *
   * @see OpenIDConnectStatefulClientInterface::updateUserInfo()
   * @see hook_openid_connect_userinfo_alter()
   */
  protected $userInfo;

  /**
   * Fetch JSON data from URL, return as array.
   *
   * @param string $url
   *   The URL to fetch from.
   * @param bool|null $use_post
   *   Whether to use POST(TRUE) or GET(FALSE, Default).
   * @param array|null $request_options
   *   Optional request options. Default is to request 'application/json'.
   *
   * @return array|null
   *   Array of fetched data or NULL on failure.
   */
  protected function fetchArray(string $url, ?bool $use_post = FALSE, ?array $request_options = NULL) : ?array {
    if (empty($request_options)) {
      $request_options = [
        'headers' => [
          'Accept' => 'application/json',
        ],
      ];
    }
    /* @var \GuzzleHttp\ClientInterface $client */
    $client = $this->httpClient;
    try {
      if ($use_post) {
        $response = $client->post($url, $request_options);
      }
      else {
        $response = $client->get($url, $request_options);
      }
      $response_data = json_decode((string) $response->getBody(), TRUE);
      if (!is_array($response_data)) {
        return NULL;
      }
      return $response_data;
    }
    catch (Exception $e) {
      $this->getLogger()->error('Failed to fetch data from @url. Details: @error_message', ['@url' => $url, '@error_message' => $e->getMessage()]);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'client_id' => '',
      'client_secret' => '',
      'issuer_identifier' => '',
      'use_discovery' => TRUE,
      'discovery_uri' => '',
      'authorization_endpoint' => '',
      'token_endpoint' => '',
      'userinfo_endpoint' => '',
      'jwks_uri' => '',
      'use_request_object' => TRUE,
      'encrypt_authorization_request' => TRUE,
      'request_object_encryption_alg_values_supported_whitelist' => '',
      'request_object_encryption_alg_values_supported_blacklist' => '',
      'request_object_encryption_enc_values_supported_whitelist' => '',
      'request_object_encryption_enc_values_supported_blacklist' => '',
      'require_id_token_encryption' => TRUE,
      'id_token_encryption_alg_values_supported_whitelist' => '',
      'id_token_encryption_alg_values_supported_blacklist' => '',
      'id_token_encryption_enc_values_supported_whitelist' => '',
      'id_token_encryption_enc_values_supported_blacklist' => '',
      'id_token_signing_alg_values_supported_whitelist' => '',
      'id_token_signing_alg_values_supported_blacklist' => '',
      'use_userinfo_endpoint' => TRUE,
      'require_userinfo_encryption' => TRUE,
      'userinfo_encryption_alg_values_supported_whitelist' => '',
      'userinfo_encryption_alg_values_supported_blacklist' => '',
      'userinfo_encryption_enc_values_supported_whitelist' => '',
      'userinfo_encryption_enc_values_supported_blacklist' => '',
      'require_userinfo_signature' => TRUE,
      'userinfo_signing_alg_values_supported_whitelist' => '',
      'userinfo_signing_alg_values_supported_blacklist' => '',
      'client_key_id' => '',
      'client_key' => '',
      'show_advanced_cryptography_settings' => FALSE,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $redirect_url = URL::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
      ]
    );
    $form['redirect_url'] = [
      '#title' => $this->t('Redirect URL'),
      '#description' => $this->t('Identity Provider will redirect the user to this URL after the authorization.'),
      '#type' => 'item',
      '#markup' => $redirect_url->toString(),
    ];
    $form['client_id'] = [
      '#title' => $this->t('Client ID'),
      '#description' => $this->t('The client ID is used to identify your service to the Identity Provider.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['client_id'],
    ];
    $form['client_secret'] = [
      '#title' => $this->t('Client secret'),
      '#description' => $this->t('The client secret is used to identify your service to the Identity Provider.'),
      '#type' => 'textfield',
      '#maxlength' => 1024,
      '#default_value' => $this->configuration['client_secret'],
    ];
    $form['issuer_identifier'] = [
      '#title' => $this->t('Identity Provider Issuer Identifier'),
      '#description' => $this->t('An HTTPS URL identifying the Identity Provider.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['issuer_identifier'],
    ];
    $form['use_discovery'] = [
      '#title' => $this->t('Use OpenID Connect Discovery'),
      '#description' => $this->t('Try to determine appropriate settings directly from the Identity Provider.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['use_discovery'],
    ];

    // @todo Hide when discovery is not enabled.
    $form['discovery_uri'] = [
      '#title' => $this->t('OpenID Connect Discovery URL'),
      '#description' => $this->t('If empty, use the standard URL: &lt;Issuer Identifier&gt;/.well-known/openid-configuration is used.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['discovery_uri'],
    ];
    // @todo Hide when discovery is enabled.
    $form['authorization_endpoint'] = [
      '#title' => $this->t('Authorization endpoint'),
      '#description' => $this->t('Identity Provider URL where users are redirected to approve the login request.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['authorization_endpoint'],
    ];
    // @todo Hide when discovery is enabled.
    $form['token_endpoint'] = [
      '#title' => $this->t('Token endpoint'),
      '#description' => $this->t('Identity Provider URL from which ID Token identifying the user will be fetched after Authorization.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['token_endpoint'],
    ];
    // @todo Hide when discovery is enabled.
    // @todo require when discovery is not enabled and userinfo endpoint is required.
    $form['userinfo_endpoint'] = [
      '#title' => $this->t('UserInfo endpoint'),
      '#description' => $this->t('Identity Provider URL from which additional user information may be fetched.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_endpoint'],
    ];
    // @todo Hide when discovery is enabled.
    $form['jwks_uri'] = [
      '#title' => $this->t('JSON Web Key Set URI'),
      '#description' => $this->t('The URL from which to fetch the public encryption and signing keys used by the Identity Provider.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['jwks_uri'],
    ];
    // @todo Validate when discovery is enabled.
    $form['use_request_object'] = [
      '#title' => $this->t('Use a Request object for the Authorization Request'),
      '#description' => $this->t('Sending the Authorization Request using a Request object may be necessary with some Identity Providers.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['use_request_object'],
    ];
    // @todo hide when request object is not used.
    $form['encrypt_authorization_request'] = [
      '#title' => $this->t('Encrypt Authorization Request'),
      '#description' => $this->t('Some Identity Providers may require encryption of the Request object.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['encrypt_authorization_request'],
    ];
    $form['require_id_token_encryption'] = [
      '#title' => $this->t('Do not accept unencrypted ID Tokens'),
      '#description' => $this->t('OpenID Connect does not mandate ID Token encryption, but some Identity Providers may do so.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['require_id_token_encryption'],
    ];
    $form['use_userinfo_endpoint'] = [
      '#title' => $this->t('Get additional Userinfo from the UserInfo endpoint'),
      '#description' => $this->t('Some Identity Providers supply all user information in the ID Token, which makes a separate UserInfo request unnecessary. Also some Identity Providers may not support the UserInfo endpoint.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['use_userinfo_endpoint'],
    ];
    $form['require_userinfo_encryption'] = [
      '#title' => $this->t('Do not acept unencrypted UserInfo responses'),
      '#description' => $this->t('OpenID Connect does not mandate UserInfo response encryption, but some Identity Providers may do so.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['require_userinfo_encryption'],
    ];

    $form['require_userinfo_signature'] = [
      '#title' => $this->t('Do not accept unsigned UserInfo responses'),
      '#description' => $this->t('OpenID Connect does not mandate UserInfo response signing, but some Identity Providers may do so.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['require_userinfo_signature'],
    ];

    $form['client_key_id'] = [
      '#title' => $this->t('Client key Key ID'),
      '#description' => $this->t('Key ID provided by the Identity Provider for your public key.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['client_key_id'],
    ];
    $form['client_key'] = [
      '#title' => $this->t('Client key'),
      '#description' => $this->t('A JSON Web Key containing for decrypting ID Token and UserInfo responses.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['client_key'],
    ];
    $form['show_advanced_cryptography_settings'] = [
      '#title' => $this->t('Show advanced cryptography settings'),
      '#description' => $this->t('Additional settings for encryption and signature algorithms.'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['show_advanced_cryptography_settings'],
    ];
    // Request related crypto settings.
    // @todo hide when request object is not used.
    $form['request_object_encryption_alg_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed request object encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_alg_values_supported_whitelist'],
    ];
    $form['request_object_encryption_alg_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden request object encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_alg_values_supported_blacklist'],
    ];
    $form['request_object_encryption_enc_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed request object encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_enc_values_supported_whitelist'],
    ];
    $form['request_object_encryption_enc_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden request object encryption algorithms for content encryption ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_enc_values_supported_blacklist'],
    ];
    // ID Token related crypto settings.
    $form['id_token_encryption_alg_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed ID Token encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_alg_values_supported_whitelist'],
    ];
    $form['id_token_encryption_alg_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_alg_values_supported_blacklist'],
    ];
    $form['id_token_encryption_enc_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed ID Token encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_enc_values_supported_whitelist'],
    ];
    $form['id_token_encryption_enc_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_enc_values_supported_blacklist'],
    ];
    $form['id_token_signing_alg_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed ID Token signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_signing_alg_values_supported_whitelist'],
    ];
    $form['id_token_signing_alg_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_signing_alg_values_supported_blacklist'],
    ];
    // Userinfo related crypto settings.
    // @todo hide when Userinfo endpoint is not used.
    $form['userinfo_encryption_alg_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_alg_values_supported_whitelist'],
    ];
    $form['userinfo_encryption_alg_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_alg_values_supported_blacklist'],
    ];
    $form['userinfo_encryption_enc_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_enc_values_supported_whitelist'],
    ];
    $form['userinfo_encryption_enc_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_enc_values_supported_blacklist'],
    ];
    $form['userinfo_signing_alg_values_supported_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_signing_alg_values_supported_whitelist'],
    ];
    $form['userinfo_signing_alg_values_supported_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_signing_alg_values_supported_blacklist'],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    // Provider label as array for StringTranslationTrait::t() argument.
    $provider = [
      '@provider' => $this->getPluginDefinition()['label'],
    ];

    // Get plugin setting values.
    $configuration = $form_state->getValues();

    // Whether a client ID is given.
    if (empty($configuration['client_id'])) {
      $form_state->setErrorByName('client_id', $this->t('The client ID is missing for @provider.', $provider));
    }
    // Whether a client secret is given.
    if (empty($configuration['client_secret'])) {
      $form_state->setErrorByName('client_secret', $this->t('The client secret is missing for @provider.', $provider));
    }

    if (!empty($configuration['use_discovery'])) {
      // For discovery, we need the issuer identifier or a discovery uri.
      $issuer_identifier = $configuration['issuer_identifier'] ?? '';
      $discovery_uri = $configuration['discovery_uri'] ?? '';
      if (empty($issuer_identifier)) {
        if (!UrlHelper::isValid($discovery_uri)) {
          $form_state->setErrorByName('discovery_uri', $this->t('If Issuer Identifier is not given, the Discovery URL for @provider must be a valid URL when using autodiscovery.', $provider));
        }
      }
      elseif (UrlHelper::isValid($issuer_identifier)) {
        // With a valida issuer identifier, the discovery uri should be valid
        // or empty.
        if (!empty($discovery_uri) && !UrlHelper::isValid($discovery_uri)) {
          $form_state->setErrorByName('discovery_uri', $this->t('When autodiscovery is used and an Issuer Identifier is given, The Discovery URL for @provider must be a valid URL or empty.', $provider));
        }
      }
      else {
        $form_state->setErrorByName('issuer_identifier', $this->t('Issuer Identifier for @provider must be a valid URL or empty.', $provider));
      }
    }
    else {
      if (empty($configuration['authorization_endpoint']) || !UrlHelper::isValid($configuration['authorization_endpoint'])) {
        $form_state->setErrorByName('authorization_endpoint', 'When not using autodiscovery, Authorization endpoint for @provider must be a valid URL.', $provider);
      }
      if (empty($configuration['token_endpoint']) || !UrlHelper::isValid($configuration['token_endpoint'])) {
        $form_state->setErrorByName('token_endpoint', 'When not using autodiscovery, Token endpoint for @provider must be a valid URL.', $provider);
      }
      if (empty($configuration['userinfo_endpoint']) || !UrlHelper::isValid($configuration['userinfo_endpoint'])) {
        if (!empty($configuration['use_userinfo_endpoint'])) {
          $form_state->setErrorByName('userinfo_endpoint', 'When not using autodiscovery, UserInfo endpoint for @provider must be a valid URL.', $provider);
        }
      }
      if (empty($configuration['jwks_uri']) || !UrlHelper::isValid($configuration['jwks_uri'])) {
        $form_state->setErrorByName('jwks_uri', 'When not using autodiscovery, the JWKS URI for @provider must be a valid URL.', $provider);
      }
    }

    // @todo Validate use_request_object when discovery is enabled.
    // @todo Validate client_key_id and client_key when encryption is required.
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
  }

  /**
   * Get the logger channel for the client plugin.
   *
   * @return \Drupal\Core\Logger\LoggerChannelInterface
   *   Logger channel for the client plugin.
   */
  protected function getLogger() : LoggerChannelInterface {
    if (empty($this->logger)) {
      $this->logger = $this->loggerFactory->get('openid_connect_' . $this->pluginId);
    }
    return $this->logger;
  }

  /**
   * Retrieve access token and ID token.
   *
   * Exchanging the authorization code that is received as the result of the
   * authentication request for an access token and an ID token.
   *
   * The ID token is a cryptographically signed JSON object encoded in base64.
   * It contains identity information about the user.
   * The access token can be sent to the login provider to obtain user profile
   * information.
   *
   * For the actual fetching of tokens, see
   * OpenIDConnectStatefulClientBase::fetchTokens(). Multiple calls to this
   * method do not cause the tokens to be refetched.
   *
   * @param string $authorization_code
   *   Authorization code received as a result of the the authorization request.
   *
   * @return array|null
   *   An associative array containing:
   *   - id_token: The ID token that holds user data.
   *   - access_token: Access token that can be used to obtain user profile
   *     information.
   *   - expire: Unix timestamp of the expiration date of the access token.
   *   On failure, NULL is returned.
   *
   * @see OpenIDConnectStatefulClientBase::fetchTokens()
   */
  final public function retrieveTokens(string $authorization_code) : ?array {
    $this->code = $authorization_code;
    // Don't fetch tokens again if we already have them.
    if (is_array($this->tokens)) {
      return $this->tokens;
    }
    $tokens = $this->fetchTokens();
    if (empty($tokens) || empty($tokens['id_token']) || empty($tokens['access_token'])) {
      return NULL;
    }
    $this->tokens = $tokens;
    $this->originalIdToken = $this->tokens['id_token'];
    $this->accessToken = $this->tokens['access_token'];
    return $this->tokens;
  }

  /**
   * {@inheritdoc}
   */
  public function getTokens() : array {
    if (!is_array($this->tokens)) {
      throw new Exception("Tokens have not been fetched.");
    }
    return $this->tokens;
  }

  /**
   * Fetch tokens from the Token endpoint if not already fetched.
   *
   * @return array|null
   *   Array of tokens or NULL on failure.
   */
  protected function fetchTokens() : ?array {
    if (!empty($this->originalIdToken) && !empty($this->accessToken)) {
      return $this->tokens;
    }
    $tokens = parent::retrieveTokens($this->code);
    if (empty($tokens) || !is_array($tokens)) {
      return NULL;
    }
    return $tokens;
  }

  /**
   * Decodes ID token to access user data.
   *
   * @param string|null $id_token
   *   This argument is here only for signature compatibility with
   *   OpenIDConnectClientInterface. It SHOULD be ignored.
   *
   * @return array|null
   *   User identity information, with at least the following keys:
   *   - iss
   *   - sub
   *   - aud
   *   - exp
   *   - iat
   *   Or NULL on failure.
   *   See the issue links below for discussion on how non-OIDC clients might
   *   be handled without them providing the expected results.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
   * @see https://www.drupal.org/project/openid_connect/issues/2999862#comment-13238172
   * @see https://www.drupal.org/project/openid_connect/issues/3077713#comment-13238361
   * @see https://www.drupal.org/project/openid_connect/issues/3076619
   */
  final public function decodeIdToken(?string $id_token = NULL) : ?array {
    if (!$this->validateIdToken()) {
      return NULL;
    }
    return $this->getDecodedIdToken();
  }

  /**
   * Decoded an url safe bas64 encoded string.
   *
   * @param string $input_url_safe_base64
   *   The string to decode.
   *
   * @return string|null
   *   The decoded string or NULL on failure.
   */
  protected function urlSafeBase64Decode(string $input_url_safe_base64) : ?string {
    $input_base64 = str_replace(['-', '_'], ['+', '/'], $input_url_safe_base64);
    $output = base64_decode($input_base64, TRUE);
    if (FALSE === $output) {
      return NULL;
    }
    return $output;
  }

  /**
   * Decode a JWT such as an ID Token.
   *
   * Encrypted tokens are not supported and signatures are not
   * verified.
   *
   * @return array
   *   The decoded JWT or NULL on failure.
   */
  protected function decodeJwtClaims(string $jwt) : array {
    $jwt_parts = explode('.', $jwt);
    switch (count($jwt_parts)) {
      case 3:
        // JWS.
        // $header_ub64 = $jwt_parts[0].
        $claims_ub64 = $jwt_parts[1];
        // $signature_ub64 = $jwt_parts[2].
        $claims_json = $this->urlSafeBase64Decode($claims_ub64);
        if (empty($claims_json)) {
          return NULL;
        }
        $claims = json_decode($claims_json, TRUE);
        if (empty($claims)) {
          return NULL;
        }
        return $claims;

      case 5:
        // @todo Implement JWE Support.
        return NULL;

      default:
        return NULL;
    }
  }

  /**
   * {@inheritdoc}
   *
   * @todo Add signature validation.
   */
  public function validateIdToken(): bool {
    if (empty($this->originalIdToken)) {
      return FALSE;
    }
    // ID Token may already have been decoded successfully.
    if (!empty($this->idToken)) {
      return TRUE;
    }
    $claims = $this->decodeJwtClaims($this->originalIdToken);
    if (empty($claims)) {
      return FALSE;
    }
    $this->idToken = $claims;
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function getDecodedIdToken(): array {
    if (empty($this->idToken)) {
      // ID Token validation may not have been attempted.
      if (!$this->validateIdToken()) {
        throw new \Exception('Attempted to get an invalid ID Token!');
      }
    }
    return $this->idToken;
  }

  /**
   * Deprecated. Prefer fetchUserinfo() and getUserInfo().
   *
   * Retrieve Userinfo from the Userinfo endpoint or ID Token and return it.
   *
   * If already fetched, just return the possibly updated UserInfo.
   *
   * Unlike OpenIDConnectClientInterface::retrieveUserInfo(), this version
   * should discard its argument. Previously acquired access token is used.
   *
   * Sub validation will be also performed and if it fails, UserInfo
   * will be discarded.
   *
   * This reference implementation may not be overridden. Instead, there are
   * separate methods for fetching and accessing the Userinfo.
   *
   * @param string|null $access_token
   *   This argument is here only for signature compatibility with
   *   OpenIDConnectClientInterface. It SHOULD be ignored.
   *
   * @return array|null
   *   An array of additional user profile information, or NULL on failure.
   *
   * @throws Exception
   *   Throws an Exception if tokens have not been fetched or are not valid.
   *
   * @see OpenIDConnectStatefulClientInterface::retrieveTokens()
   * @see OpenIDConnectStatefulClientInterface::fetchUserInfo()
   * @see OpenIDConnectStatefulClientInterface::getUserInfo()
   */
  final public function retrieveUserInfo(?string $access_token = NULL) : ?array {
    if (!$this->fetchUserInfo() || !$this->validateSub()) {
      return [];
    }
    return $this->getUserInfo();
  }

  /**
   * {@inheritdoc}
   */
  public function fetchUserInfo() : bool {
    // Don't try fetching if we don't have a valid starting point.
    if (empty($this->accessToken) || !$this->validateIDToken()) {
      return FALSE;
    }
    // Don't refetch needlessly.
    if (!empty($this->userInfo) && $this->validateSub()) {
      return TRUE;
    }
    $userinfo = parent::retrieveUserInfo($this->accessToken);
    if (empty($userinfo) || !is_array($userinfo)) {
      return FALSE;
    }
    $this->originalUserInfo = $userinfo;
    $this->userInfo = $userinfo;
    // If sub in the UserInfo does not match the sub in the ID Token,
    // UserInfo response MUST NOT be used.
    if (!$this->validateSub()) {
      $this->originalUserInfo = NULL;
      $this->userInfo = NULL;
      return FALSE;
    }
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function getUserInfo(): array {
    if (empty($this->userInfo)) {
      throw new \Exception('Userinfo not present!');
    }
    return $this->userInfo;
  }

  /**
   * {@inheritdoc}
   */
  public function updateUserInfo(array $userinfo) {
    $this->userInfo = $userinfo;
  }

  /**
   * {@inheritdoc}
   */
  final public function validateSub() : bool {
    // If sub was already validated once, that is sufficient for response
    // validation purposes.
    if (!empty($this->originalSub) && !empty($this->sub)) {
      return TRUE;
    }
    if (empty($this->idToken)) {
      throw new \Exception('Can not validate sub before decoding ID Token');
    }
    elseif (empty($this->userInfo)) {
      throw new \Exception('Can not validate sub before fetching User Info');
    }
    $sub_id_token = $this->idToken['sub'];
    if (empty($sub_id_token)) {
      return FALSE;
    }
    $sub_userinfo = $this->originalUserInfo['sub'];
    if (empty($sub_userinfo)) {
      return FALSE;
    }
    if ($sub_id_token !== $sub_userinfo) {
      return FALSE;
    }
    if (mb_strlen($sub_id_token) > 255) {
      return FALSE;
    }
    $this->originalSub = $sub_id_token;
    try {
      if (!$this->additionalSubValidation()) {
        return FALSE;
      }
      $this->sub = $this->originalSub;
      // Allow client to normalize sub.
      $normalized_sub = $this->getNormalizedSub();
      if (empty($normalized_sub)) {
        return FALSE;
      }
      $this->sub = $normalized_sub;
      return TRUE;
    }
    catch (Exception $e) {
      // Clear sub since validation or normalization failed.
      $this->sub = NULL;
      $variables = [
        '@provider' => $this->pluginId,
        '@error_message' => $e->getMessage(),
      ];
      $this->getLogger()->error('An unpexpected error occured in sub validation or normalization using @provider. Details: @error_message', $variables);
      return FALSE;
    }
  }

  /**
   * Perform additional validations on sub by overriding this method.
   *
   * @return bool
   *   TRUE if sub is valid, FALSE if not.
   */
  protected function additionalSubValidation() : bool {
    return empty($this->originalSub) ? FALSE : TRUE;
  }

  /**
   * {@inheritdoc}
   */
  final public function getSub() : string {
    if (empty($this->sub)) {
      // Sub validation may not have been attempted.
      if (!$this->validateSub()) {
        throw new \Exception('Attempted to get an invalid sub');
      }
    }
    return $this->getNormalizedSub();
  }

  /**
   * Normalize the sub by overriding this method.
   *
   * This allows a plugin to provide a sub that uniquely identifies a single
   * user when using identity providers where a single user's sub may change
   * over time or depends on the method by which they authenticate themselves
   * to the identity provider. Examples: Azure AAD, Finnish Trust Network,
   * other chained authentication systems.
   *
   * @return string
   *   The sub.
   *
   * @throws Exception
   *   Throws an Exception if the sub is not validated or is empty.
   */
  protected function getNormalizedSub() : string {
    if (empty($this->sub)) {
      throw new \Exception('Attempted to get an invalid sub!');
    }
    return $this->sub;
  }

  /**
   * This default implementation yields user mapping to the caller.
   *
   * @inheritDoc
   */
  public function findUser(?OpenIDConnectAuthmap $authmap = NULL): ?UserInterface {
    return NULL;
  }

}
