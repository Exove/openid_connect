<?php

namespace Drupal\openid_connect\Plugin;

use Drupal\openid_connect\OpenIDConnectAuthmap;
use Drupal\user\UserInterface;

/**
 * Defines an interface for stateful OpenID Connect client plugins.
 *
 * @see OpenIDConnectStatefulClientBase
 * @see OpenIDConnectStalessClientWrapper
 * @see OpenIDConnectClientInterface
 * @see OpenIDConnectClientBase
 */
interface OpenIDConnectStatefulClientInterface extends OpenIDConnectClientInterface {

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
  public function decodeIdToken(?string $id_token = NULL) : ?array;

  /**
   * Check if the ID Token is valid.
   *
   * @return bool
   *   Whether the ID Token was valid or not.
   *
   * @see OpenIDConnectStatefulClientInterface::retrieveTokens()
   */
  public function validateIdToken() : bool;

  /**
   * Get the decoded ID Token.
   *
   * "Replaces" OpenIDConnectClientInterface::decodeIdToken($id_token).
   *
   * @return array
   *   The decoded ID Token as an associative array.
   *
   * @throws Exception
   *   Throws an Exception if the ID Token is not valid.
   */
  public function getDecodedIdToken() : array;

  /**
   * Check if the sub is valid.
   *
   * Authorize and Token end points must provide the same sub, if both are used.
   * It also MUST NOT exceed 255 characters in length.
   *
   * @return bool
   *   FALSE if not valid, TRUE if valid.
   *
   * @throws Exception
   *   Throws an Exception if ID Token has not been decoded or UserInfo
   *   has not been fetched.
   */
  public function validateSub() : bool;

  /**
   * Get the sub.
   *
   * The client may provide a sub different from the one actually received, e.g.
   * in order to support use cases where another claim is used as a unique
   * identifier for the person in question.
   *
   * @return string
   *   The sub.
   *
   * @throws Exception
   *   Throws an Exception if the sub is not valid or can't be validated.
   *
   * @see OpenIDConnectStatefulClientInterface::validateSub()
   */
  public function getSub() : string;

  /**
   * Retrieve Userinfo from the Userinfo endpoint or ID Token and return it.
   *
   * Unlike OpenIDConnectClientInterface::retrieveUserInfo(), this version
   * should discard its argument. Previously acquired access token is used.
   *
   * If Userinfo has already been fetched, implementations MAY just return
   * the information already held by them, possibly having been updated by
   * OpenIDConnectStatefulClientInterface::updateUserInfo().
   *
   * Sub validation will be also performed and if it fails, UserInfo
   * will be discarded.
   *
   * The reference implementation provided by OpenIDConnectStatefulClientBase
   * may not be overridden. Instead, there are separate methods for fetching
   * and accessing the Userinfo.
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
  public function retrieveUserInfo(?string $access_token = NULL) : ?array;

  /**
   * Fetch Userinfo from the Userinfo endpoint or ID Token.
   *
   * Sub validation SHOULD be also performed and if it fails, UserInfo
   * SHOULD be discarded, and the default implementation does this, but
   * does not prevent extending classes from omitting that part.
   *
   * To customize actual fetching of UserInfo, override this method
   * instead of retrieveUserInfo().
   *
   * @return bool
   *   Whether fetching was successul or not.
   *
   * @see OpenIDConnectStatefulClientInterface::validateSub()
   * @see OpenIDConnectStatefulClientInterface::getUserInfo()
   */
  public function fetchUserInfo() : bool;

  /**
   * Get UserInfo (or claims.)
   *
   * UserInfo may be retrieved from the UserInfo endpoint or it may rely
   * on claims provided in the ID Token. Please note that subsequent calls
   * may return different results. The default uses of this, in:
   *   - OpenIDConnect::completeAuthorization() and
   *   - OpenIDConnect::connectCurrentUser()
   * assume that that the only methods that do change the UserInfo after
   * initially retrieving it are:
   *   - OpenIDConnectStatefulClientInterface::updateUserInfo()
   *   - OpenIDConnectStatefulClientInterface::findUser()
   *
   * @return array
   *   An associative array of claims about the user.
   *
   * @throws Exception
   *   Throws an Exception if Userinfo was not successfully fetched.
   *
   * @see OpenIDConnectStatefulClientInterface::retrieveUserInfo()
   * @see OpenIDConnectStatefulClientInterface::updateUserInfo()
   * @see OpenIDConnectStatefulClientInterface::findUser()
   */
  public function getUserInfo() : array;

  /**
   * Update UserInfo.
   *
   * This is mainly intended to be used to update possible changes resulting
   * from invoking hook_openid_connect_userinfo_alter(). See the notes on
   * OpenIDConnectStatefulClientInterface::getUserInfo() on expectations
   * regarding mutation of UserInfo.
   *
   * @param array $userinfo
   *   The updated userinfo.
   *
   * @throws Exception
   *   Throws an Exception if Userinfo hasn't been successfully fetched.
   *
   * @see OpenIDConnectStatefulClientInterface::getUserInfo()
   * @see OpenIDConnectStatefulClientInterface::findUser()
   */
  public function updateUserInfo(array $userinfo);

  /**
   * Optionally provide user mapping.
   *
   * Implementing this method allows the client to bypass the default
   * sub to user account mapping done by
   * OpenIDConnect::completeAuthorization() and
   * OpenIDConnect::connectCurrentUser() by returning a user account.
   *
   * See the notes on OpenIDConnectStatefulClientInterface::getUserInfo()
   * on expectations regarding mutation of UserInfo.
   *
   * @param \Drupal\openid_connect\OpenIDConnectAuthmap|null $authmap
   *   An OpenID Connect Authmap.
   *
   * @return \Drupal\user\UserInterface|null
   *   A user matching the authorization results.
   *
   * @see OpenIDConnectStatefulClientInterface::getUserInfo()
   * @see OpenIDConnectStatefulClientInterface::updateUserInfo()
   * @see OpenIDConnect::completeAuthorization()
   * @see OpenIDConnect::connectCurrentUser()
   */
  public function findUser(?OpenIDConnectAuthmap $authmap = NULL) : ?UserInterface;

}
