<?php

namespace Drupal\openid_connect\Plugin\OpenIDConnectClient;

use Drupal\openid_connect\Plugin\OpenIDConnectClientInterface;
use Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientBase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Wrapper for stateless OpenID Connect clients.
 *
 * Used as a compatibility layer for legacy stateless clients.
 *
 * @OpenIDConnectClient(
 *   id = "stateless_client_wrapper",
 *   label = @Translation("Stateless Client Wrapper")
 * )
 */
class OpenIDConnectStatelessClientWrapper extends OpenIDConnectStatefulClientBase {

  /**
   * A fake 'sub' value for non-OIDC clients.
   *
   * @see OpenIDConnectClientInterface::byPassSubValidation()
   */
  const FAKE_ID_TOKEN_SUB = 'openid_connect_stateless_client_wrapper_fake_sub';

  /**
   * A fake 'original id token' for non-OIDC clients.
   *
   * @see OpenIDConnectClientInterface::byPassSubValidation()
   */
  const FAKE_ORIGINAL_ID_TOKEN = 'openid_connect_stateless_client_wrapper_fake_original_id_token';

  /**
   * The stateless client plugin to wrap around.
   *
   * @var \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface
   */
  protected $statelessClient;

  /**
   * Configuration for the plugin wrapped around.
   *
   * @var array
   */
  protected $statelessClientConfiguration;

  /**
   * Initialize stateful client emulation for a stateless client.
   *
   * The assumption here is that emulating a stateful client will start before
   * the tokens have been fetched.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface $client
   *   The stateless client to wrap around.
   *
   * @see OpenIdConnectStatelessClientWrapper::initializeWithTokens()
   */
  public function initialize(OpenIDConnectClientInterface $client) {
    $this->statelessClient = $client;
  }

  /**
   * Initialize stateful client emulation for a stateless client.
   *
   * The assumption here is that emulating a stateful client will start after
   * the tokens have been fetched.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface $client
   *   The stateless client to wrap around.
   * @param array $tokens
   *   The tokens as retrieved by OpenIDConnectClientInterface::retrieveTokens()
   *
   * @throws Exception
   *   Throws an Exception if ID Token or Access Token are not present in
   *   tokens, but they are not required to be nonempty.
   *
   * @see OpenIdConnectStatelessClientWrapper::initialize()
   */
  public function initializeWithTokens(OpenIDConnectClientInterface $client, array $tokens) {
    $this->initialize($client);

    if (!isset($tokens['id_token'])) {
      // The id_token key must exist, but an empty one can be forgiven
      // for clients explicitly opting out of sub validation.
      if (!array_key_exists('id_token', $tokens) || !$client->byPassSubValidation()) {
        throw new \Exception('Missing ID Token');
      }
      else {
        // Inject a fake id token for non-OIDC clients that opt out of
        // sub validation.
        $tokens['id_token'] = self::FAKE_ORIGINAL_ID_TOKEN;
      }
    }
    if (!isset($tokens['access_token'])) {
      throw new \Exception('Missing Access Token');
    }
    // Set the tokens.
    $this->tokens = $tokens;
    $this->originalIdToken = $this->tokens['id_token'];
    $this->accessToken = $this->tokens['access_token'];
  }

  /**
   * Throw an Exception if the stateless client is missing.
   *
   * @throws Exception
   *   Throws an Exception if the stateless client is missing.
   */
  protected function requireStatelessClient() {
    if (empty($this->statelessClient)) {
      throw new \Exception('OpenIDConnectStatelessClientWrapper used without initialization!');
    }
  }

  /**
   * Get the Plugin Id of the stateless client wrapped around if there is one.
   *
   * If the wrapper has not been initialized with a stateless plugin, the plugin
   * id of the wrapper itself is returned.
   *
   * @return string
   *   Plugin Id of the stateless client if set, or the wrapper's id if not.
   */
  public function getPluginId() {
    if (!empty($this->statelessClient)) {
      return $this->statelessClient->getPluginId();
    }
    return $this->pluginId;
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() : array {
    $this->requireStatelessClient();
    return $this->statelessClient->getEndpoints();
  }

  /**
   * {@inheritdoc}
   */
  public function getClientScopes(): ?array {
    $this->requireStatelessClient();
    return $this->statelessClient->getClientScopes();
  }

  /**
   * {@inheritdoc}
   */
  public function authorize(?string $scope = 'openid email') : Response {
    $this->requireStatelessClient();
    return $this->statelessClient->authorize($scope);
  }

  /**
   * {@inheritdoc}
   */
  protected function fetchTokens(): ?array {
    $this->requireStatelessClient();
    $tokens = $this->statelessClient->retrieveTokens($this->code);
    if (empty($tokens) || !is_array($tokens)) {
      return NULL;
    }
    return $tokens;
  }

  /**
   * {@inheritdoc}
   */
  public function validateIdToken() : bool {
    $this->requireStatelessClient();
    if (empty($this->originalIdToken)) {
      return FALSE;
    }
    // ID Token may already have been decoded successfully.
    if (!empty($this->idToken)) {
      return TRUE;
    }
    $claims = $this->statelessClient->decodeIdToken($this->originalIdToken);
    if (empty($claims)) {
      if (is_null($claims) || !$this->statelessClient->byPassSubValidation()) {
        // NULL is always a failure.
        return FALSE;
      }
      // If the client has opted out of sub validation, accept a non-NULL,
      // result, but the "decoded id token" must still not be empty later on,
      // so to remedy that, inject a fake 'sub'.
      $claims = ['sub' => self::FAKE_ID_TOKEN_SUB];
    }
    $this->idToken = $claims;
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function fetchUserInfo() : bool {
    $this->requireStatelessClient();
    // Don't try fetching if we don't have a valid starting point.
    if (empty($this->accessToken) || !$this->validateIDToken()) {
      return FALSE;
    }
    // Don't refetch needlessly.
    if (!empty($this->userInfo) && $this->validateSub()) {
      return TRUE;
    }
    $userinfo = $this->statelessClient->retrieveUserInfo($this->accessToken);
    if (empty($userinfo) || !is_array($userinfo)) {
      return FALSE;
    }
    $this->originalUserInfo = $userinfo;
    $this->userInfo = $userinfo;
    // If we are wrapping around a client that is not actually implementing
    // OpenID Connect, and the client explicitly foregoes sub validation,
    // fake the sub for the client, as long as there is one in UserInfo, and
    // there is not one already from the ID Token.
    if ($this->statelessClient->byPassSubValidation()) {
      if (!empty($userinfo['sub'])) {
        $sub_userinfo = $userinfo['sub'];
        // If the client opts out of sub validation, the sub should be either
        // empty, or a fake one generated by this wrapper.
        if (!empty($this->idToken['sub']) && $this->idToken['sub'] != self::FAKE_ID_TOKEN_SUB) {
          // This is obviously an error worthy of logging, but give the regular
          // sub validation a chance.
          $this->getLogger()->error(
            "Bypassing of sub validation was requested by @provider, but sub was included in the ID Token.",
            ['@provider' => $this->getPluginId()]
          );
        }
        else {
          // Fullfill the requirement of identical subs in ID Token and
          // Userinfo by injecting it into Userinfo.
          $this->idToken['sub'] = $sub_userinfo;
        }
      }
    }
    // If sub in the UserInfo does not match the sub in the ID Token,
    // UserInfo response MUST NOT be used.
    if (!$this->validateSub()) {
      $this->originalUserInfo = NULL;
      $this->userInfo = NULL;
      return FALSE;
    }
    return TRUE;
  }

}