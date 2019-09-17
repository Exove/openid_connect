<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\Component\Plugin\PluginBase;
use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\openid_connect\OpenIDConnectStateToken;
use Exception;
use GuzzleHttp\ClientInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;

/**
 * Base class for stateless OpenID Connect client plugins.
 *
 * New client plugins should extend OpenIDConnectStatefulClientBase instead.
 *
 * @see OpenIDConnectStatefulClientInterface
 * @see OpenIDConnectStatefulClientBase
 * @see https://www.drupal.org/project/openid_connect/issues/3076619
 */
abstract class OpenIDConnectClientBase extends PluginBase implements OpenIDConnectClientInterface, ContainerFactoryPluginInterface {
  use StringTranslationTrait;

  /**
   * The request stack used to access request globals.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * The HTTP client to fetch the feed data with.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * The logger factory used for logging.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * Whether sub validation should be bypassed for this client.
   *
   * See OpenIDConnectClientInterface::byPassSubValidation() for
   * details on the subject and its security implications.
   *
   * @var bool
   *
   * @see \Drupal\openid_connect\Plugin\OpenIdConnectClientInterface::byPassSubValidation()
   * @see https://www.drupal.org/project/openid_connect/issues/2999862
   */
  protected $byPassSubValidation = FALSE;

  /**
   * The minimum set of scopes for this client.
   *
   * @var array|null
   *
   * @see \Drupal\openid_connect\OpenIDConnectClaims::getScopes()
   */
  protected $clientScopes = NULL;

  /**
   * The constructor.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin identifier.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The http client.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
      array $configuration,
      $plugin_id,
      $plugin_definition,
      RequestStack $request_stack,
      ClientInterface $http_client,
      LoggerChannelFactoryInterface $logger_factory
  ) {
    parent::__construct(
      $configuration,
      $plugin_id,
      $plugin_definition
    );

    $this->requestStack = $request_stack;
    $this->httpClient = $http_client;
    $this->loggerFactory = $logger_factory;
    $this->setConfiguration($configuration);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(
      ContainerInterface $container,
      array $configuration,
      $plugin_id,
      $plugin_definition
  ) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('request_stack'),
      $container->get('http_client'),
      $container->get('logger.factory')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getConfiguration() {
    return $this->configuration;
  }

  /**
   * {@inheritdoc}
   */
  public function setConfiguration(array $configuration) {
    $this->configuration = NestedArray::mergeDeep(
      $this->defaultConfiguration(),
      $configuration
    );
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'client_id' => '',
      'client_secret' => '',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function calculateDependencies() {
    return [];
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
      '#type' => 'item',
      '#markup' => $redirect_url->toString(),
    ];
    $form['client_id'] = [
      '#title' => $this->t('Client ID'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['client_id'],
    ];
    $form['client_secret'] = [
      '#title' => $this->t('Client secret'),
      '#type' => 'textfield',
      '#maxlength' => 1024,
      '#default_value' => $this->configuration['client_secret'],
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
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
  }

  /**
   * Implements OpenIDConnectClientInterface::getEndpoints().
   */
  public function getEndpoints() : array {
    throw new Exception('Unimplemented method getEndpoints().');
    // Eliminate complaints about no return statement.
    // @codingStandardsIgnoreStart
    return [];
    // @codingStandardsIgnoreEnd
  }

  /**
   * {@inheritdoc}
   */
  public function getClientScopes(): ?array {
    return $this->clientScopes;
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
    $url_options = [
      'query' => [
        'client_id' => $this->configuration['client_id'],
        'response_type' => 'code',
        'scope' => $scope,
        'redirect_uri' => $redirect_uri->getGeneratedUrl(),
        'state' => OpenIDConnectStateToken::create(),
      ],
    ];
    return $url_options;
  }

  /**
   * Implements OpenIDConnectClientInterface::authorize().
   *
   * @param string|null $scope
   *   A string of scopes.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   A trusted redirect response object.
   *   The OpenIDConnectClientInterface requires the return type to be
   *   \Symfony\Component\HttpFoundation\Response , so that is used
   *   for the return type declaration, but
   *   \Drupal\Core\Routing\TrustedRedirectResponse is a subclass of that.
   *   This mismatch between the documented and declared types can be
   *   fixed in PHP 7.4.
   */
  public function authorize(?string $scope = 'openid email') : Response {
    $language_none = \Drupal::languageManager()
      ->getLanguage(LanguageInterface::LANGCODE_NOT_APPLICABLE);
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language_none,
      ]
    )->toString(TRUE);

    $url_options = $this->getUrlOptions($scope, $redirect_uri);

    $endpoints = $this->getEndpoints();
    // Clear _GET['destination'] because we need to override it.
    $this->requestStack->getCurrentRequest()->query->remove('destination');
    $authorization_endpoint = Url::fromUri($endpoints['authorization'], $url_options)->toString(TRUE);

    $response = new TrustedRedirectResponse($authorization_endpoint->getGeneratedUrl());
    // We can't cache the response, since this will prevent the state to be
    // added to the session. The kill switch will prevent the page getting
    // cached for anonymous users when page cache is active.
    \Drupal::service('page_cache_kill_switch')->trigger();

    return $response;
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveIDToken().
   *
   * {@inheritdoc}
   *
   * @param string $authorization_code
   *   A authorization code string.
   *
   * @return array|null
   *   A result array or NULL on failure.
   */
  public function retrieveTokens(string $authorization_code) : ?array {
    // Exchange `code` for access token and ID token.
    $language_none = \Drupal::languageManager()
      ->getLanguage(LanguageInterface::LANGCODE_NOT_APPLICABLE);
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language_none,
      ]
    )->toString();
    $endpoints = $this->getEndpoints();

    $request_options = [
      'form_params' => [
        'code' => $authorization_code,
        'client_id' => $this->configuration['client_id'],
        'client_secret' => $this->configuration['client_secret'],
        'redirect_uri' => $redirect_uri,
        'grant_type' => 'authorization_code',
      ],
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];

    /* @var \GuzzleHttp\ClientInterface $client */
    $client = $this->httpClient;
    try {
      $response = $client->post($endpoints['token'], $request_options);
      $response_data = json_decode((string) $response->getBody(), TRUE);

      // Make sure the result is an array.
      if (!is_array($response_data)) {
        return NULL;
      }

      // Expected result.
      $tokens = [
        'id_token' => isset($response_data['id_token']) ? $response_data['id_token'] : NULL,
        'access_token' => isset($response_data['access_token']) ? $response_data['access_token'] : NULL,
      ];
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = REQUEST_TIME + $response_data['expires_in'];
      }
      if (array_key_exists('refresh_token', $response_data)) {
        $tokens['refresh_token'] = $response_data['refresh_token'];
      }
      return $tokens;
    }
    catch (Exception $e) {
      $variables = [
        '@message' => 'Could not retrieve tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_' . $this->pluginId)
        ->error('@message. Details: @error_message', $variables);
      return NULL;
    }
  }

  /**
   * Implements OpenIDConnectClientInterface::decodeIdToken().
   *
   * {@inheritdoc}
   */
  public function decodeIdToken(?string $id_token = NULL) : ?array {
    if (empty($id_token)) {
      return NULL;
    }
    // @codingStandardsIgnoreStart
    list($headerb64, $claims64, $signatureb64) = explode('.', $id_token);
    // @codingStandardsIgnoreEnd
    $claims64 = str_replace(['-', '_'], ['+', '/'], $claims64);
    $claims64 = base64_decode($claims64);
    $claims = json_decode($claims64, TRUE);
    // Make sure the result is an array before returning it.
    if (!is_array($claims)) {
      return NULL;
    }
    return $claims;
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveUserInfo().
   *
   * {@inheritdoc}
   *
   * @param string|null $access_token
   *   An access token string.
   *
   * @return array|null
   *   A result array or NULL on failure.
   */
  public function retrieveUserInfo(?string $access_token = NULL) : ?array {
    if (empty($access_token)) {
      return NULL;
    }
    $request_options = [
      'headers' => [
        'Authorization' => 'Bearer ' . $access_token,
        'Accept' => 'application/json',
      ],
    ];
    $endpoints = $this->getEndpoints();

    $client = $this->httpClient;
    try {
      $response = $client->get($endpoints['userinfo'], $request_options);
      $response_data = (string) $response->getBody();

      // Make sure the result is an array before returning it.
      $userinfo = json_decode($response_data, TRUE);
      if (!is_array($userinfo)) {
        return NULL;
      }
      return $userinfo;
    }
    catch (Exception $e) {
      $variables = [
        '@message' => 'Could not retrieve user profile information',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_' . $this->pluginId)
        ->error('@message. Details: @error_message', $variables);
      return NULL;
    }
  }

  /**
   * Whether to bypass sub validation. Returning TRUE may be dangerous.
   *
   * See OpenIDConnectClientInterface::byPassSubValidation() for
   * details on the subject and its security implications.
   *
   * {@inheritDoc}
   *
   * @return bool
   *   Whether to require that both the ID Token and UserInfo contain a
   *   sub claim that is nonempty and equal in both.
   *
   * @see \Drupal\openid_connect\Plugin\OpenIdConnectClientInterface::byPassSubValidation()
   * @see https://www.drupal.org/project/openid_connect/issues/2999862
   */
  public function byPassSubValidation(): bool {
    return $this->byPassSubValidation;
  }

}
