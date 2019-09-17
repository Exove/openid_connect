<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\Component\Plugin\ConfigurablePluginInterface;
use Drupal\Component\Plugin\PluginInspectionInterface;
use Drupal\Core\Plugin\PluginFormInterface;

/**
 * Defines an interface for OpenID Connect client plugins.
 */
interface OpenIDConnectClientInterface extends ConfigurablePluginInterface, PluginFormInterface, PluginInspectionInterface {

  /**
   * Returns an array of endpoints.
   *
   * @return array
   *   An array with the following keys:
   *   - authorization: The full url to the authorization endpoint.
   *   - token: The full url to the token endpoint.
   *   - userinfo: The full url to the userinfo endpoint.
   */
  public function getEndpoints();

  /**
   * Gets an array of of scopes.
   *
   * This method allows a client to override the default minimum set of scopes
   * assumed by OpenIDConnectClaims::getScopes();
   *
   * @return array|null
   *   An array of scopes or NULL to use defaults.
   *
   * @see \Drupal\openid_connect\OpenIDConnectClaims::getScopes()
   */
  public function getClientScopes() : ?array;

  /**
   * Redirects the user to the authorization endpoint.
   *
   * The authorization endpoint authenticates the user and returns them
   * to the redirect_uri specified previously with an authorization code
   * that can be exchanged for an access token.
   *
   * @param string $scope
   *   Name of scope(s) that with user consent will provide access to otherwise
   *   restricted user data. Defaults to "openid email".
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   A response object.
   */
  public function authorize($scope = 'openid email');

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
   * @param string $authorization_code
   *   Authorization code received as a result of the the authorization request.
   *
   * @return array
   *   An associative array containing:
   *   - id_token: The ID token that holds user data.
   *   - access_token: Access token that can be used to obtain user profile
   *     information.
   *   - expire: Unix timestamp of the expiration date of the access token.
   */
  public function retrieveTokens($authorization_code);

  /**
   * Decodes ID token to access user data.
   *
   * @param string $id_token
   *   The encoded ID token containing the user data.
   *
   * @return array
   *   User identity information.
   */
  public function decodeIdToken($id_token);

  /**
   * Retrieves user info: additional user profile data.
   *
   * @param string $access_token
   *   Access token.
   *
   * @return array
   *   User profile information.
   */
  public function retrieveUserInfo($access_token);

  /**
   * Whether to bypass sub validation or not when using this client.
   *
   * The OpenID Connect specification REQUIRES that an ID Token containing
   * a MANDATORY 'sub' claim is present in the response from the Token
   * endpoint. However, this is not currently required by the module as
   * long as it is present in the UserInfo, or injected there by
   * hook_openid_connect_userinfo_alter(), and the module already provides
   * plugins that are using Oauth or custom protocols instead of
   * OpenID Connect.
   *
   * When using OpenID Connect, not verifying that the sub claim of the
   * UserInfo response equals the sub claim of the ID Token opens up the
   * the possibility of token substitution attacks. For this reason, DO NOT
   * return TRUE from this method unless your plugin is a wrapper around
   * another protocol.
   *
   * @return bool
   *   Whether to require that both the ID Token and UserInfo contain a
   *   sub claim that is nonempty and equal in both.
   *
   * @see https://www.drupal.org/project/openid_connect/issues/2999862
   */
  public function byPassSubValidation() : bool;

}
