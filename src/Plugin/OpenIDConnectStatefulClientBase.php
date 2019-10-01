<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\openid_connect\OpenIDConnectAuthmap;
use Drupal\user\UserInterface;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\openid_connect\OpenIDConnectJwtHelper;
use Drupal\openid_connect\OpenIDConnectStateToken;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;

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
   * The OpenID Connect JWT helper service.
   *
   * @var \Drupal\openid_connect\OpenIDConnectJwtHelper
   */
  protected $jwtHelper;

  /**
   * Default path component for OpenID Connect Discovery URL.
   */
  const OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration';

  /**
   * Mandatory fields for discovered configuration.
   *
   * @var array
   */
  protected $requiredFieldsForDiscoveredConfiguration = [
    'issuer',
    'authorization_endpoint',
    'token_endpoint',
    'userinfo_endpoint',
    'jwks_uri',
    'response_types_supported',
  ];

  /**
   * OpenID Connect Discovery provided Identity Provider configuration.
   *
   * If discovery is used, the first configuration response is cached here for
   * the lifetime of the client.
   *
   * @var array
   */
  protected $discoveredConfiguration = [];

  /**
   * Possible uses for algorithm selection.
   *
   * These correspond to available values in OpenID Connect Discovery provided
   * configuration advertising available or accepted signature (signing_alg),
   * key encryption (encryption_alg) and content encryption (encryption_enc)
   * algorithms.
   *
   * @var array
   *
   * @see OpenIDConnectStatefulClientBase::selectAlgorithms()
   */
  protected $algorithmSelectionUses = [
    'request_object_key_encryption' => [
      'discovered_configuration_key' => 'request_object_encryption_alg_values_supported',
      'configuration_whitelist_key' => 'request_object_encryption_alg_values_whitelist',
      'configuration_blacklist_key' => 'request_object_encryption_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
    'request_object_content_encryption' => [
      'discovered_configuration_key' => 'request_object_encryption_enc_values_supported',
      'configuration_whitelist_key' => 'request_object_encryption_enc_values_whitelist',
      'configuration_blacklist_key' => 'request_object_encryption_enc_values_blacklist',
    ],
    'request_object_signing' => [
      'discovered_configuration_key' => 'request_object_signing_alg_values_supported',
      'configuration_whitelist_key' => 'request_object_signing_alg_values_whitelist',
      'configuration_blacklist_key' => 'request_object_signing_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
    'id_token_key_encryption' => [
      'discovered_configuration_key' => 'id_token_encryption_alg_values_supported',
      'configuration_whitelist_key' => 'id_token_encryption_alg_values_whitelist',
      'configuration_blacklist_key' => 'id_token_encryption_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
    'id_token_content_encryption' => [
      'discovered_configuration_key' => 'id_token_encryption_enc_values_supported',
      'configuration_whitelist_key' => 'id_token_encryption_enc_values_whitelist',
      'configuration_blacklist_key' => 'id_token_encryption_enc_values_blacklist',
    ],
    'id_token_signing' => [
      'discovered_configuration_key' => 'id_token_signing_alg_values_supported',
      'configuration_whitelist_key' => 'id_token_signing_alg_values_whitelist',
      'configuration_blacklist_key' => 'id_token_signing_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
    'userinfo_key_encryption' => [
      'discovered_configuration_key' => 'userinfo_encryption_alg_values_supported',
      'configuration_whitelist_key' => 'userinfo_encryption_alg_values_whitelist',
      'configuration_blacklist_key' => 'userinfo_encryption_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
    'userinfo_content_encryption' => [
      'discovered_configuration_key' => 'userinfo_encryption_enc_values_supported',
      'configuration_whitelist_key' => 'userinfo_encryption_enc_values_whitelist',
      'configuration_blacklist_key' => 'userinfo_encryption_enc_values_blacklist',
    ],
    'userinfo_signing' => [
      'discovered_configuration_key' => 'userinfo_signing_alg_values_supported',
      'configuration_whitelist_key' => 'userinfo_signing_alg_values_whitelist',
      'configuration_blacklist_key' => 'userinfo_signing_alg_values_blacklist',
      'use_key_hint' => TRUE,
    ],
  ];

  /**
   * An array of endpoints.
   *
   * Should contain the following endpoints:
   *   - discovery (may be empty)
   *   - authorization
   *   - token
   *   - userinfo
   *   - jwks.
   * If only discovery is configured, it will be used to determine the rest.
   *
   * @var array
   */
  protected $endpoints = [];

  /**
   * The minimum set of scopes for this client.
   *
   * @var array|null
   *
   * @see \Drupal\openid_connect\OpenIDConnectClaims::getScopes()
   */
  protected $clientScopes = NULL;

  /**
   * JSON Web Key Set (JWKS) containing the Identity Provider's public keys.
   *
   * @var \Jose\Component\Core\JWKSet
   */
  protected $providerJwkSet;

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
   * Get the OpenID Connect JWT helper service.
   *
   * @return \Drupal\openid_connect\OpenIDConnectJwtHelper
   *   The OpenID Connect JWT helper service.
   */
  protected function getJwtHelper() : OpenIDConnectJwtHelper {
    if (empty($this->jwtHelper)) {
      $this->jwtHelper = \Drupal::service('openid_connect.jwt_helper');
    }
    return $this->jwtHelper;
  }

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
    $response_body = $this->fetch($url, $use_post, $request_options);
    if (is_null($response_body)) {
      // Fetch should have already logged the problem, so just return.
      return NULL;
    }
    $response_data = json_decode($response_body, TRUE);
    if (!is_array($response_data)) {
      return NULL;
    }
    return $response_data;
  }

  /**
   * Fetch data from URL, return response body as string.
   *
   * @param string $url
   *   The URL to fetch from.
   * @param bool|null $use_post
   *   Whether to use POST(TRUE) or GET(FALSE, Default).
   * @param array|null $request_options
   *   Optional request options. Default is to request 'application/json'.
   *
   * @return string|null
   *   String of fetched data or NULL on failure.
   */
  protected function fetch(string $url, ?bool $use_post = FALSE, ?array $request_options = NULL) : ?string {
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
      $response_body = (string) $response->getBody();
      return $response_body;
    }
    catch (Exception $e) {
      $this->getLogger()->error('Failed to fetch data from @url. Details: @error_message', ['@url' => $url, '@error_message' => $e->getMessage()]);
      return NULL;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getDiscoveryUrl() : ?string {
    $discovery_uri = $this->configuration['discovery_uri'];
    if (empty($discovery_uri)) {
      $discovery_uri = $this->configuration['issuer_identifier'] . self::OIDC_DISCOVERY_PATH;
    }
    if (!UrlHelper::isValid($discovery_uri, TRUE)) {
      return NULL;
    }
    return $discovery_uri;
  }

  /**
   * Get a valid endpoint URL or NULL on failure.
   *
   * @param string $endpoint_key
   *   The key of the endpoint, see getEndpoints().
   *
   * @return string|null
   *   The URL for the endpoint or NULL if it is not a valid URL.
   */
  protected function getValidEndpointUrl(string $endpoint_key) : ?string {
    if (empty($this->endpoints[$endpoint_key])) {
      $this->getEndpoints();
    }
    $url = $this->endpoints[$endpoint_key];
    if (!UrlHelper::isValid($url, TRUE)) {
      return NULL;
    }
    return $url;
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthorizationEndpoint() : ?string {
    return $this->getValidEndpointUrl('authorization');
  }

  /**
   * {@inheritdoc}
   */
  public function getTokenEndpoint() : ?string {
    return $this->getValidEndpointUrl('token');
  }

  /**
   * {@inheritdoc}
   */
  public function getUserInfoEndpoint() : ?string {
    return $this->getValidEndpointUrl('userinfo');
  }

  /**
   * {@inheritdoc}
   */
  public function getJwksUrl() : ?string {
    return $this->getValidEndpointUrl('jwks');
  }

  /**
   * Get an array from a configuration field of comma separated values.
   *
   * @param string $key
   *   Configuration key.
   *
   * @return array|null
   *   The resulting array, or NULL if the key is not set, the value is
   *   empty(), or if the value results in an empty array.
   */
  public function getArrayFromCsvConfiguration(string $key) : ?array {
    if (empty($this->configuration[$key])) {
      return NULL;
    }
    $as_array = explode(',', $this->configuration);
    if (empty($as_array)) {
      return NULL;
    }
    return $as_array;
  }

  /**
   * Discover configuration from the Identity Provider if appropriate.
   *
   * @param bool|null $force_refresh
   *   If TRUE, fetch configuration again even if already fetched.
   *
   * @return bool
   *   TRUE if configuration discovery was successfull, or if it is disabled.
   *   FALSE if discovery is enabled but it failed.
   */
  protected function discoverConfiguration(?bool $force_refresh = FALSE) : bool {
    if (empty($this->configuration['use_discovery'])) {
      // If discovery is disabled, we're okay.
      return TRUE;
    }
    if (!empty($this->discoverConfiguration) && !$force_refresh) {
      return TRUE;
    }
    $discovery_uri = $this->getDiscoveryUrl();
    if (empty($discovery_uri)) {
      $this->getLogger()->error('No valid URL for OIDC Connect Discovery!');
      return FALSE;
    }
    $config = $this->fetchArray($discovery_uri);
    if (empty($config)) {
      return FALSE;
    }
    foreach ($this->requiredFieldsForDiscoveredConfiguration as $field) {
      if (empty($config[$field])) {
        $this->getLogger()->error('The OpenID Connect Discovery provided configuration is missing the mandatory field @field', ['@field' => $field]);
        return FALSE;
      }
    }
    $this->discoveredConfiguration = $config;
    return TRUE;
  }

  /**
   * Returns an array of endpoints.
   *
   * @return array
   *   An array with the following keys:
   *   - discovery: The OpenID Connect Discovery URL or empty if not set.
   *   - authorization: The full url to the authorization endpoint.
   *   - token: The full url to the token endpoint.
   *   - userinfo: The full url to the userinfo endpoint.
   *   - jwks: The full url to the JWKS used for signing responses.
   */
  public function getEndpoints() : array {
    if (!isset($this->endpoints['discovery'])) {
      $discovery_uri = $this->getDiscoveryUrl();
      if (empty($discovery_uri)) {
        $this->endpoints['discovery'] = '';
      }
      else {
        $this->endpoints['discovery'] = $discovery_uri;
      }
    }
    // Configuration key => endpoint array key.
    $required_endpoints = [
      'authorization_endpoint' => 'authorization',
      'token_endpoint' => 'token',
      'jwks_uri' => 'jwks',
    ];
    if ($this->configuration['use_userinfo_endpoint']) {
      $required_endpoints['userinfo_endpoint'] = 'userinfo';
    }
    if ($this->configuration['use_discovery'] && $this->discoverConfiguration()) {
      foreach ($required_endpoints as $config_key => $endpoint_key) {
        $this->endpoints[$endpoint_key] = $this->discoveredConfiguration[$config_key];
      }
    }
    // @todo Consider if this is the right way and document it.
    // If endpoints are set explicitly, override possible discovered values.
    foreach ($required_endpoints as $config_key => $endpoint_key) {
      if (!empty($this->configuration[$config_key])) {
        $this->endpoints[$endpoint_key] = $this->configuration[$config_key];
      }
    }
    return $this->endpoints;
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
      'scope' => '',
      'acr_values' => '',
      'use_request_object' => TRUE,
      'encrypt_authorization_request' => TRUE,
      'request_object_encryption_alg_values_whitelist' => '',
      'request_object_encryption_alg_values_blacklist' => '',
      'request_object_encryption_enc_values_whitelist' => '',
      'request_object_encryption_enc_values_blacklist' => '',
      'require_id_token_encryption' => TRUE,
      'id_token_encryption_alg_values_whitelist' => '',
      'id_token_encryption_alg_values_blacklist' => '',
      'id_token_encryption_enc_values_whitelist' => '',
      'id_token_encryption_enc_values_blacklist' => '',
      'id_token_signing_alg_values_whitelist' => '',
      'id_token_signing_alg_values_blacklist' => '',
      'use_userinfo_endpoint' => TRUE,
      'require_userinfo_encryption' => TRUE,
      'userinfo_encryption_alg_values_whitelist' => '',
      'userinfo_encryption_alg_values_blacklist' => '',
      'userinfo_encryption_enc_values_whitelist' => '',
      'userinfo_encryption_enc_values_blacklist' => '',
      'require_userinfo_signature' => TRUE,
      'userinfo_signing_alg_values_whitelist' => '',
      'userinfo_signing_alg_values_blacklist' => '',
      'client_key_id' => '',
      'client_key' => '',
      'show_advanced_cryptography_settings' => FALSE,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form['redirect_url'] = [
      '#title' => $this->t('Redirect URL'),
      '#description' => $this->t('Identity Provider will redirect the user to this URL after the authorization.'),
      '#type' => 'item',
      '#markup' => $this->getRedirectUrl(TRUE)->toString(),
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
    $form['scope'] = [
      '#title' => $this->t('Authorization Request Scope'),
      '#description' => $this->t('This controls what kind of access to the user information is requested from the Identity Provider. This should be usually left empty to use the default value of "openid email".'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['scope'],
    ];
    $form['acr_values'] = [
      '#title' => $this->t('Authentication Context Class Reference values'),
      '#description' => $this->t('Space separated ACR values in order of decreasing preference. Some Identity Providers may allow these to affect how the user should identify themselves to the Identity Provider.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['acr_values'],
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
      '#type' => 'checkbox',
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
    $form['request_object_encryption_alg_values_whitelist'] = [
      '#title' => $this->t('Allowed request object encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_alg_values_whitelist'],
    ];
    $form['request_object_encryption_alg_values_blacklist'] = [
      '#title' => $this->t('Forbidden request object encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_alg_values_blacklist'],
    ];
    $form['request_object_encryption_enc_values_whitelist'] = [
      '#title' => $this->t('Allowed request object encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_enc_values_whitelist'],
    ];
    $form['request_object_encryption_enc_values_blacklist'] = [
      '#title' => $this->t('Forbidden request object encryption algorithms for content encryption ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['request_object_encryption_enc_values_blacklist'],
    ];
    // ID Token related crypto settings.
    $form['id_token_encryption_alg_values_whitelist'] = [
      '#title' => $this->t('Allowed ID Token encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_alg_values_whitelist'],
    ];
    $form['id_token_encryption_alg_values_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_alg_values_blacklist'],
    ];
    $form['id_token_encryption_enc_values_whitelist'] = [
      '#title' => $this->t('Allowed ID Token encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_enc_values_whitelist'],
    ];
    $form['id_token_encryption_enc_values_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_encryption_enc_values_blacklist'],
    ];
    $form['id_token_signing_alg_values_whitelist'] = [
      '#title' => $this->t('Allowed ID Token signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_signing_alg_values_whitelist'],
    ];
    $form['id_token_signing_alg_values_blacklist'] = [
      '#title' => $this->t('Forbidden ID Token signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['id_token_signing_alg_values_blacklist'],
    ];
    // Userinfo related crypto settings.
    // @todo hide when Userinfo endpoint is not used.
    $form['userinfo_encryption_alg_values_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_alg_values_whitelist'],
    ];
    $form['userinfo_encryption_alg_values_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo encryption algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_alg_values_blacklist'],
    ];
    $form['userinfo_encryption_enc_values_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_enc_values_whitelist'],
    ];
    $form['userinfo_encryption_enc_values_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo encryption algorithms for content encryption ("enc")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_encryption_enc_values_blacklist'],
    ];
    $form['userinfo_signing_alg_values_whitelist'] = [
      '#title' => $this->t('Allowed UserInfo signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of algorithms in decreasing order of preference.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_signing_alg_values_whitelist'],
    ];
    $form['userinfo_signing_alg_values_blacklist'] = [
      '#title' => $this->t('Forbidden UserInfo signature algorithms for key management ("alg")'),
      '#description' => $this->t('A comma separated list of forbidden algorithms.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_signing_alg_values_blacklist'],
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
   * Fetch the JSON Web Key Set containing the Identity Provider's public keys.
   *
   * @param bool|null $force_refresh
   *   If TRUE, fetch keys even if already fetched. Default FALSE.
   *
   * @return bool
   *   TRUE on success, FALSE on failure.
   */
  protected function fetchJwks(?bool $force_refresh = FALSE) : bool {
    if (!empty($this->providerJwkSet) && !$force_refresh) {
      return TRUE;
    }
    $jwks_uri = $this->getJwksUrl();
    if (empty($jwks_uri)) {
      $this->getLogger()->error('Missing Identity Provider JWKS URL');
      return FALSE;
    }
    $jwks = $this->fetchArray($jwks_uri);
    try {
      $jwkset = JWKSet::createFromKeyData($jwks);
      if (count($jwkset) === 0) {
        $this->getLogger()->error('Provider JWKS contained no keys');
        return FALSE;
      }
      $this->providerJwkSet = $jwkset;
      return TRUE;
    }
    catch (Exception $e) {
      $this->getLogger()->error('Failed to get Identity Provider JWKS or it contains no keys.');
      return FALSE;
    }
  }

  /**
   * Get the Identity Provider's public key for signing.
   *
   * If there are multiple keys, try to return the most preferred one
   * based on configuration. If there are no keys or no available keys
   * are allowd by current configuration, return NULL.
   *
   * @return \Jose\Component\Core\JWK|null
   *   A JWK object containing preferred signing keys or NULL on failure.
   *
   * @todo implement key filtering.
   */
  protected function getProviderSigningKey() : ?JWK {
    if (!$this->fetchJwks()) {
      return NULL;
    }
    $key = $this->providerJwkSet->selectKey('sig');
    if (empty($key)) {
      $this->getLogger()->error('Could not find an Identity Provider key for signing.');
    }
    return $key;
  }

  /**
   * Get the Identity Provider's public key for encryption.
   *
   * If there are multiple keys, try to return the most preferred one
   * based on configuration. If there are no keys or no available keys
   * are allowd by current configuration, return NULL.
   *
   * @return \Jose\Component\Core\JWK|null
   *   A JWK object containing preferred encryption keys or NULL on failure.
   *
   * @todo implement key filtering.
   */
  protected function getProviderEncryptionKey() : ?JWK {
    if (!$this->fetchJwks()) {
      return NULL;
    }
    $key = $this->providerJwkSet->selectKey('enc');
    if (empty($key)) {
      $this->getLogger()->error('Could not find an Identity Provider key for encryption.');
    }
    return $key;
  }

  /**
   * Get client encryption key as a JWK.
   *
   * @return \Jose\Component\Core\JWK|null
   *   The client encryption key or NULL on failure.
   */
  protected function getClientEncryptionKey() : ?JWK {
    $client_key_json = $this->configuration['client_key'];
    if (empty($client_key_json)) {
      $this->getLogger()->error('Client key is missing or empty');
      return NULL;
    }
    try {
      $client_jwk = JWK::createFromJson($client_key_json);
      return $client_jwk;
    }
    catch (\Exception $e) {
      $this->getLogger()->error('Client key loading failed. Details: @error_message', ['@error_message' => $e->getMessage()]);
      return NULL;
    }
  }

  /**
   * Select an algorithm by use case depending on configuration.
   *
   * - If a whitelist has been configured, it will be used to select the
   * preferred algorithms from the ones available per discovered configuration.
   * - If there is no discovered configuration the whitelist will be used
   * instead of that.
   * - If a key with an 'alg' parameter on it is provided, that will be the
   * first result for key encryption and signing uses, unless it is missing
   * from a nonempty whitelist or included on a nonempty blacklist.
   * - If a blacklist has been configured, algorithms on it are removed, even if
   * a key suggesting such an algorithm is provided.
   *
   * Note that the order of the results is undefined without a whitelist,
   * other than the guarantee that a non-blacklisted algorithm from a key
   * will be the first for key encryption and signing uses.
   *
   * @param string $use
   *   See OpenIDConnectStatefulClientBase::algorithmSelectionUses.
   *   Possible values:
   *    - request_object_key_encryption
   *    - request_object_content_encryption
   *    - request_object_signing
   *    - id_token_key_encryption
   *    - id_token_content_encryption
   *    - id_token_signing
   *    - userinfo_key_encryption
   *    - userinfo_content_encryption
   *    - userinfo_signing.
   * @param \Jose\Component\Core\JWK|null $key
   *   An optional key to inform the selection.
   *
   * @return array
   *   An array of algorithms names. If a whitelist was configured, the
   *   names are in whitelist order, unless a key was provided as well,
   *   in which case the key alg has the highest precedence. The list may
   *   be empty.
   */
  protected function selectAlgorithms(string $use, ?JWK $key = NULL) : array {
    $configuration_keys = $this->algorithmSelectionUses[$use] ?? NULL;
    if (empty($configuration_keys)) {
      $this->getLogger()->error('Tried to select an algorithm for an unrecognized use @use', ['@use' => $use]);
      return [];
    }
    $discovered_configuration_key = $configuration_keys['discovered_configuration_key'] ?? NULL;
    $configuration_whitelist_key = $configuration_keys['configuration_whitelist_key'] ?? NULL;
    $configuration_blacklist_key = $configuration_keys['configuration_blacklist_key'] ?? NULL;
    $use_key_hint = $this->algorithmSelectionUses[$use]['use_key_hint'] ?? FALSE;
    if (empty($discovered_configuration_key) || empty($configuration_whitelist_key || empty($configuration_blacklist_key))) {
      $this->getLogger()->error('Tried to select an algorithm for a use @use that is not properly supported', ['@use' => $use]);
      return [];
    }
    $provider_algorithms = [];
    if ($this->discoverConfiguration() && !empty($this->discoveredConfiguration[$discovered_configuration_key] && is_array($this->discoveredConfiguration[$discovered_configuration_key]))) {
      $provider_algorithms = $this->discoveredConfiguration[$discovered_configuration_key];
    }
    $client_whitelist = $this->getArrayFromCsvConfiguration($configuration_whitelist_key) ?? [];
    $client_blacklist = $this->getArrayFromCsvConfiguration($configuration_blacklist_key) ?? [];
    $selected_algorithms = $provider_algorithms;
    // If a whitelist is provided, use that instead of the provider list.
    if (!empty($client_whitelist)) {
      $selected_algorithms = $client_whitelist;
      // If the provider list is not empty, include only those present.
      if (!empty($provider_algorithms)) {
        $selected_algorithms = array_intersect($client_whitelist, $provider_algorithms);
      }
    }
    // If algorithm from key should be used and one is provided, include it
    // as the first one, unless it is missing from a nonempty whitelist.
    if ($use_key_hint && !empty($key) && $key->has('alg')) {
      $key_algorithm = $key->get('alg');
      if (!empty($key_algorithm)) {
        if (empty($client_whitelist) || in_array($key_algorithm, $client_whitelist)) {
          $selected_algorithms = array_unique([$key_algorithm] + $selected_algorithms);
        }
      }
    }
    // Remove blacklisted algorithms.
    if (!empty($client_blacklist)) {
      $selected_algorithms = array_diff($selected_algorithms, $client_blacklist);
    }
    return $selected_algorithms;
  }

  /**
   * Encode the Authorization Request as a Request Object JWT.
   *
   * The Authorization Request parameters are rolled into a single JWT
   * as specified in OIDC specification section 6.1. Depending on client
   * configuration, the result may be an encrypted one (JWE), a signed one
   * (JWS) or a nested JWT, i.e. an encrypted token containing a signed token.
   *
   * Note that only encryption is supported for now.
   *
   * @param array $query
   *   The Authorization Request parameters.
   *
   * @return string
   *   A JWT containing a Request Object as per OIDC specification section 6.1.
   *
   * @throws Exception
   *   Throws an Exception if an appropriate Request Object can not be built.
   */
  protected function getRequestObject(array $query) : string {
    if (!$this->configuration['encrypt_authorization_request']) {
      $error = 'Unencrypted request object not supported';
      $this->getLogger()->error($error);
      throw new \Exception($error);
    }
    $jwk = $this->getProviderEncryptionKey();
    if (empty($jwk)) {
      $error = 'Could not get Identity Provider encryption key.';
      $this->getLogger()->error($error);
      throw new \Exception($error);
    }
    $key_encryption_algorithms = $this->selectAlgorithms('request_object_key_encryption', $jwk);
    $key_encryption_algorithm = reset($key_encryption_algorithms);
    if (empty($key_encryption_algorithm)) {
      throw new \Exception('Could not select request object key encryption algorithm.');
    }
    $content_encryption_algorithms = $this->selectAlgorithms('request_object_content_encryption');
    $content_encryption_algorithm = reset($content_encryption_algorithms);
    if (empty($content_encryption_algorithm)) {
      throw new \Exception('Could not select request object content encryption algorithm.');
    }
    $jwt_helper = $this->getJwtHelper();
    $request_jwe_token = $jwt_helper->buildJwe(
      $query,
      $jwk,
      $content_encryption_algorithm,
      $key_encryption_algorithm
    );
    return $request_jwe_token;
  }

  /**
   * Get URL options for the Authorization endpoint.
   *
   * @param string $scope
   *   A string of scopes.
   * @param \Drupal\Core\Url $redirect_uri
   *   The redirect Url.
   *
   * @return array
   *   An array of options for generating the full Authorization endpoint URL.
   *
   * @todo Add a nonce, save it and verify it afterwards.
   * @todo Add encryption and/or signing of query depending on client settings.
   */
  protected function getUrlOptions(string $scope, Url $redirect_uri) : array {
    $query = [
      'client_id' => $this->configuration['client_id'],
      'response_type' => 'code',
      'scope' => $scope,
      'redirect_uri' => $redirect_uri->toString(),
      'state' => OpenIDConnectStateToken::create(),
    ];
    // Add acr_values only if specified.
    $acr_values = $this->configuration['acr_values'] ?? NULL;
    if (!empty($acr_values)) {
      $query['acr_values'] = $acr_values;
    }
    if ($this->configuration['use_request_object']) {
      $request = $this->getRequestObject($query);
      // The client_id and response_type are required outside of the request
      // as well to be valid OAuth 2.0.
      $query = [
        'client_id' => $this->configuration['client_id'],
        'response_type' => 'code',
        'request' => $request,
      ];
    }
    $url_options = [
      'query' => $query,
    ];
    return $url_options;
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
   * @todo Support unencrypted tokens.
   * @todo Take algorithm selection configuration properly into account.
   * @todo Allow rejecting tokens that are only encrypted?
   */
  public function validateIdToken(): bool {
    if (empty($this->originalIdToken)) {
      return FALSE;
    }
    // ID Token may already have been decoded successfully.
    if (!empty($this->idToken) && is_array($this->idToken)) {
      return TRUE;
    }
    $token = $this->originalIdToken;
    $jwt_helper = $this->getJwtHelper();
    $token_parts = explode('.', $token);
    $encrypted_token = count($token_parts) === 5 ? $token : NULL;
    $signed_token = count($token_parts) === 3 ? $token : NULL;
    $payload = NULL;
    if (!empty($encrypted_token)) {
      // Handle encrypted token.
      $client_key = $this->getClientEncryptionKey();
      if (empty($client_key)) {
        $this->getLogger()->error('Could not get a client key for decrypting ID Token.');
        return FALSE;
      }
      $key_encryption_algorithms = $this->selectAlgorithms('id_token_key_encryption', $client_key);
      $content_encryption_algorithms = $this->selectAlgorithms('id_token_content_encryption', $client_key);
      $jwe_payload = $jwt_helper->decryptJwe(
        $encrypted_token,
        $client_key,
        $key_encryption_algorithms,
        $content_encryption_algorithms
      );
      if (empty($jwe_payload)) {
        $this->getLogger()->error('Failed to decrypt ID Token.');
        return FALSE;
      }
      // Is the token also signed?
      $payload = json_decode($jwe_payload, TRUE);
      if (!is_array($payload)) {
        $payload = NULL;
        $jwe_payload_parts = explode('.', $jwe_payload);
        if (count($jwe_payload_parts) === 3) {
          // Looks like the payload is a JWS.
          $signed_token = $jwe_payload;
        }
        else {
          $this->getLogger()->error('Encrypted ID Token payload was neither a JSON object or a JWS.');
          return FALSE;
        }
      }
      else {
        // The token was only encrypted, get the claims.
        $this->idToken = $payload;
        return TRUE;
      }
    }
    elseif (empty($encrypted_token) && !empty($this->configuration['require_id_token_encryption'])) {
      $this->getLogger()->error('ID Token is required to be encrypted, but it is not.');
      return FALSE;
    }

    if (!empty($signed_token)) {
      $provider_key = $this->getProviderSigningKey();
      if (empty($provider_key)) {
        $this->getLogger()->error('Can not verify ID Token signature without Identity Provider Signature key');
        return FALSE;
      }
      $signature_algorithms = $this->selectAlgorithms('id_token_signing', $provider_key);
      $jws_payload = $jwt_helper->loadAndVerifyJws(
        $signed_token,
        $provider_key,
        $signature_algorithms
      );
      $payload = json_decode($jws_payload, TRUE);
      if (!is_array($payload)) {
        $payload = NULL;
        $this->getLogger()->error('Encrypted ID Token payload was not a JSON object.');
        return FALSE;
      }
    }
    if (!is_array($payload) || empty($payload)) {
      $this->getLogger()->error('Unknown error in ID Token validation');
      return FALSE;
    }
    $this->idToken = $payload;
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
    // If UserInfo endpoint should not be used, pick up UserInfo from
    // the ID Token.
    if (empty($this->configuration['use_userinfo_endpoint'])) {
      $userinfo = $this->idToken;
    }
    else {
      // @todo handle case where userinfo is not JWE+JWS
      $request_options = [
        'headers' => [
          'Authorization' => 'Bearer ' . $this->accessToken,
          'Accept' => 'application/json',
        ],
      ];
      $userinfo_response = $this->fetch(
        $this->getUserInfoEndpoint(),
        TRUE,
        $request_options
      );
      // If unencrypted, unsigned responses are allowed, try that first.
      $userinfo = NULL;
      if (empty($this->configuration['require_userinfo_encryption']) && empty($this->configuration['require_userinfo_signature'])) {
        $userinfo = json_decode($userinfo_response, TRUE);
      }
      if (empty($userinfo) || !is_array($userinfo)) {
        $userinfo = $this->processUserInfoJwt($userinfo_response);
      }
    }
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
   * Decrypt and verify a JWT UserInfo response.
   *
   * @param string $userinfo_response
   *   The body of the userinfo response.
   *
   * @return array|null
   *   An array of UserInfo claims or NULL on failure, or if the UserInfo
   *   response encryption or signature is not acceptable with
   *   current configuration.
   */
  protected function processUserInfoJwt(string $userinfo_response) : ?array {
    $jwt_helper = $this->getJwtHelper();
    $token = $userinfo_response;
    $token_parts = explode('.', $token);
    $encrypted_token = count($token_parts) === 5 ? $token : NULL;
    $signed_token = count($token_parts) === 3 ? $token : NULL;
    $payload = NULL;
    if (!empty($encrypted_token)) {
      // Handle encrypted token.
      $client_key = $this->getClientEncryptionKey();
      if (empty($client_key)) {
        $this->getLogger()->error('Could not get a client key for decrypting UserInfo Response.');
        return NULL;
      }
      $key_encryption_algorithms = $this->selectAlgorithms('userinfo_key_encryption', $client_key);
      $content_encryption_algorithms = $this->selectAlgorithms('userinfo_content_encryption', $client_key);
      $jwe_payload = $jwt_helper->decryptJwe(
        $encrypted_token,
        $client_key,
        $key_encryption_algorithms,
        $content_encryption_algorithms
      );
      if (empty($jwe_payload)) {
        $this->getLogger()->error('Failed to decrypt UserInfo.');
        return NULL;
      }
      // Is the token also signed?
      $payload = json_decode($jwe_payload, TRUE);
      if (!is_array($payload)) {
        $payload = NULL;
        $jwe_payload_parts = explode('.', $jwe_payload);
        if (count($jwe_payload_parts) === 3) {
          // Looks like the payload is a JWS.
          $signed_token = $jwe_payload;
        }
        else {
          $this->getLogger()->error('Encrypted UserInfo response was neither a JSON object or a JWS.');
          return NULL;
        }
      }
      else {
        // The response was only encrypted, return the claims.
        return $payload;
      }
    }
    elseif (empty($encrypted_token) && !empty($this->configuration['require_userinfo_encryption'])) {
      $this->getLogger()->error('UserInfo is required to be encrypted, but it is not.');
      return NULL;
    }

    if (!empty($signed_token)) {
      $provider_key = $this->getProviderSigningKey();
      if (empty($provider_key)) {
        $this->getLogger()->error('Can not verify UserInfo signature without Identity Provider Signature key');
        return NULL;
      }
      $signature_algorithms = $this->selectAlgorithms('userinfo_signing', $provider_key);
      $jws_payload = $jwt_helper->loadAndVerifyJws(
        $signed_token,
        $provider_key,
        $signature_algorithms
      );
      $payload = json_decode($jws_payload, TRUE);
      if (!is_array($payload)) {
        $payload = NULL;
        $this->getLogger()->error('Encrypted UserInfo payload was not a JSON object.');
        return NULL;
      }
    }
    elseif (!empty($this->configuration['require_userinfo_signature'])) {
      $this->getLogger()->error('UserInfo is required to be signed, but it was not.');
      return NULL;
    }
    if (!is_array($payload) || empty($payload)) {
      $this->getLogger()->error('Unknown error in UserInfo validation');
      return NULL;
    }
    return $payload;
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
