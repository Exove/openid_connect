<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\openid_connect\OpenIDConnectAuthmap;
use Drupal\user\UserInterface;

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
   * OpenIDConnectStatefulClientBase::fetchTokens();
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
