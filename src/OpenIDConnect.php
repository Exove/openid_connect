<?php

namespace Drupal\openid_connect;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\openid_connect\Plugin\OpenIDConnectClientInterface;
use Drupal\user\UserDataInterface;
use Drupal\user\UserInterface;
use Drupal\Component\Utility\EmailValidatorInterface;
use Drupal\Component\Render\MarkupInterface;
use Drupal\openid_connect\Plugin\OpenIDConnectClientManager;
use Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientInterface;

/**
 * Main service of the OpenID Connect module.
 */
class OpenIDConnect {
  use StringTranslationTrait;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The OpenID Connect authmap service.
   *
   * @var \Drupal\openid_connect\OpenIDConnectAuthmap
   */
  protected $authmap;

  /**
   * The entity field manager.
   *
   * @var \Drupal\Core\Entity\EntityFieldManagerInterface
   */
  protected $entityFieldManager;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected $currentUser;

  /**
   * The user data service.
   *
   * @var \Drupal\user\UserDataInterface
   */
  protected $userData;

  /**
   * The User entity storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $userStorage;

  /**
   * The Messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * The module handler.
   *
   * @var Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * The email validator service.
   *
   * @var \Egulias\EmailValidator\EmailValidatorInterface
   */
  protected $emailValidator;

  /**
   * The OpenID Connect logger channel.
   *
   * @var Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * OpenID Connect Client Plugin Manager.
   *
   * @var \Drupal\openid_connect\Plugin\OpenIDConnectClientManager
   */
  protected $pluginManager;

  /**
   * State of the authorization.
   *
   * @var string
   */
  protected $authorizationState = 'authorization_not_attempted';

  /**
   * Possible authorization state constants.
   */
  const AUTHORIZATION_NOT_ATTEMPTED = 'authorization_not_attempted';

  const ATTEMPTING_AUTHORIZATION = 'attempting_authorization';

  const SUCCESSFULL_LOGIN = 'successfull_login';
  const SUCCESSFULL_CONNECTION = 'successfull_connection';

  const ERROR_AUTHORIZATION_FAILED = 'error_authorization_failed';
  const ERROR_AUTHORIZATION_DENIED = 'error_authorization_denied';
  const ERROR_INVALID_EMAIL = 'error_invalid_email';
  const ERROR_EMAIL_TAKEN = 'error_email_taken';
  const ERROR_REGISTRATION_RESTRICTED = 'error_registration_restricted';
  const ERROR_USER_INACTIVE = 'error_user_inactive';
  const ERROR_ANOTHER_USER_CONNECTED = 'error_another_user_connected';

  /**
   * Possible authorization error messages.
   *
   * @var \Drupal\Component\Render\MarkupInterface[]
   */
  protected $authorizationErrorMessages = [];

  /**
   * Construct an instance of the OpenID Connect service.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\openid_connect\OpenIDConnectAuthmap $authmap
   *   The OpenID Connect authmap service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity manager.
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entity_field_manager
   *   The entity field manager.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   Account proxy for the currently logged-in user.
   * @param \Drupal\user\UserDataInterface $user_data
   *   The user data service.
   * @param \Egulias\EmailValidator\EmailValidatorInterface $email_validator
   *   The email validator service.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   *   The module handler.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger
   *   A logger channel factory instance.
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientManager $plugin_manager
   *   OpenID Connect Client Plugin Manager.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    OpenIDConnectAuthmap $authmap,
    EntityTypeManagerInterface $entity_type_manager,
    EntityFieldManagerInterface $entity_field_manager,
    AccountProxyInterface $current_user,
    UserDataInterface $user_data,
    EmailValidatorInterface $email_validator,
    MessengerInterface $messenger,
    ModuleHandler $module_handler,
    LoggerChannelFactoryInterface $logger,
    OpenIDConnectClientManager $plugin_manager
  ) {
    $this->configFactory = $config_factory;
    $this->authmap = $authmap;
    $this->userStorage = $entity_type_manager->getStorage('user');
    $this->entityFieldManager = $entity_field_manager;
    $this->currentUser = $current_user;
    $this->userData = $user_data;
    $this->emailValidator = $email_validator;
    $this->messenger = $messenger;
    $this->moduleHandler = $module_handler;
    $this->logger = $logger->get('openid_connect');
    $this->pluginManager = $plugin_manager;
  }

  /**
   * Return user properties that can be ignored when mapping user profile info.
   *
   * @param array $context
   *   Optional: Array with context information, if this function is called
   *   within the context of user authorization.
   *   Defaults to an empty array.
   */
  public function userPropertiesIgnore(array $context = []) {
    $properties_ignore = [
      'uid',
      'uuid',
      'langcode',
      'preferred_langcode',
      'preferred_admin_langcode',
      'name',
      'pass',
      'mail',
      'status',
      'created',
      'changed',
      'access',
      'login',
      'init',
      'roles',
      'default_langcode',
    ];
    $this->moduleHandler->alter('openid_connect_user_properties_ignore', $properties_ignore, $context);
    // Invoke deprecated hook with deprecation error message.
    // @todo Remove in RC1.
    $this->moduleHandler->alterDeprecated('hook_openid_connect_user_properties_to_skip_alter() is deprecated and will be removed in 8.x-1.x-rc1.', 'openid_connect_user_properties_to_skip', $properties_ignore);

    $properties_ignore = array_unique($properties_ignore);
    return array_combine($properties_ignore, $properties_ignore);
  }

  /**
   * Get the 'sub' property from the user data and/or user claims.
   *
   * The 'sub' (Subject Identifier) is a unique ID for the external provider to
   * identify the user.
   *
   * @param array $user_data
   *   The user data as returned from
   *   OpenIDConnectClientInterface::decodeIdToken().
   * @param array $userinfo
   *   The user claims as returned from
   *   OpenIDConnectClientInterface::retrieveUserInfo().
   * @param bool $bypass_validation
   *   Whether to bypass the requirement for both the ID Token ($user_data)
   *   and UserInfo to contain the sub. See
   *   OpenIDConnectClientInterface::byPassSubValidation() for details and
   *   security implications.
   *
   * @return string|false
   *   The sub, or FALSE if there was an error.
   *
   * @see \Drupal\openid_connect\Plugin\OpenIdConnectClientInterface::byPassSubValidation()
   */
  public function extractSub(array $user_data, array $userinfo, bool $bypass_validation = FALSE) {
    if (!isset($user_data['sub']) && !isset($userinfo['sub'])) {
      return FALSE;
    }
    elseif (!isset($user_data['sub'])) {
      // Unless validation is explicitly disabled, both should contain the sub.
      if (!$bypass_validation) {
        return FALSE;
      }
      return $userinfo['sub'];
    }
    elseif (isset($userinfo['sub']) && $user_data['sub'] != $userinfo['sub']) {
      return FALSE;
    }
    return $user_data['sub'];
  }

  /**
   * Set authorization state and optionally display an error message.
   *
   * @param string $authorization_state
   *   Should be one of the class state constants.
   * @param \Drupal\Component\Render\MarkupInterface|null $error_message
   *   An optional error message to display to user.
   */
  protected function setAuthorizationState(string $authorization_state, MarkupInterface $error_message = NULL) {
    $this->authorizationState = $authorization_state;

    // Reset messages on a new attempt.
    if ($authorization_state === self::ATTEMPTING_AUTHORIZATION) {
      $this->authorizationErrorMessages = [];
    }

    // Add the error to stack if provided.
    if (!empty($error_message)) {
      $this->authorizationErrorMessages[] = $error_message;
    }
  }

  /**
   * Add an authorization error message without changing the state.
   *
   * @param \Drupal\Component\Render\MarkupInterface $error_message
   *   The error message to add.
   */
  protected function addAuthorizationErrorMessage(MarkupInterface $error_message) {
    $this->authorizationErrorMessages[] = $error_message;
  }

  /**
   * Get authorization state constant.
   *
   * Note that if multiple authorizations are attempted, this will only
   * reflect the state of the last one.
   *
   * @return string
   *   Value of the class constant representing the state of last authorization.
   */
  public function getAuthorizationState() : string {
    return $this->authorizationState;
  }

  /**
   * Get authorization error messages.
   *
   * Note that if multiple authorizations are attempted, this will only
   * reflect the errors of the last one.
   *
   * @return \Drupal\Component\Render\MarkupInterface[]
   *   Error messages for the last authorization attempt.
   */
  public function getAuthorizationErrorMessages() : array {
    return $this->authorizationErrorMessages;
  }

  /**
   * Complete the authorization after tokens have been retrieved.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface $client
   *   The client.
   * @param array $tokens
   *   The tokens as returned from
   *   OpenIDConnectClientInterface::retrieveTokens().
   * @param string|array &$destination
   *   The path to redirect to after authorization.
   *
   * @return bool
   *   TRUE on success, FALSE on failure.
   */
  public function completeAuthorization(OpenIDConnectClientInterface $client, array $tokens, &$destination) {
    if ($this->currentUser->isAuthenticated()) {
      throw new \RuntimeException('User already logged in');
    }

    $this->setAuthorizationState(self::ATTEMPTING_AUTHORIZATION);

    $common_error_context = [
      '@provider' => $client->getPluginId(),
    ];

    $user_data = $client->decodeIdToken($tokens['id_token']);
    $userinfo = $client->retrieveUserInfo($tokens['access_token']);

    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
    ];
    $this->moduleHandler->alter('openid_connect_userinfo', $userinfo, $context);

    if ($userinfo && empty($userinfo['email'])) {
      $message = 'No e-mail address provided by @provider';
      $variables = ['@provider' => $client->getPluginId()];
      $this->logger->error($message . ' (@code @error). Details: @details', $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_FAILED,
        $this->t('Logging in with @provider could not be completed due to an error.', $common_error_context)
      );
      return FALSE;
    }

    $sub = $this->extractSub($user_data, $userinfo, $client->byPassSubValidation());
    if (empty($sub)) {
      $message = 'No "sub" found from @provider';
      $variables = ['@provider' => $client->getPluginId()];
      $this->logger->error($message . ' (@code @error). Details: @details', $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_FAILED,
        $this->t('Logging in with @provider could not be completed due to an error.', $common_error_context)
      );
      return FALSE;
    }

    /* @var \Drupal\user\UserInterface $account */
    $account = $this->authmap->userLoadBySub($sub, $client->getPluginId());
    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
      'userinfo' => $userinfo,
      'sub' => $sub,
    ];
    $results = $this->moduleHandler->invokeAll('openid_connect_pre_authorize', [
      $account,
      $context,
    ]);

    // Deny access if any module returns FALSE.
    if (in_array(FALSE, $results, TRUE)) {
      $message = 'Login denied for @email via pre-authorize hook.';
      $variables = ['@email' => $userinfo['email']];
      $this->logger->error($message, $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_DENIED,
        $this->t('Logging in with @provider was denied.', $common_error_context)
      );
      return FALSE;
    }

    // If any module returns an account, set local $account to that.
    foreach ($results as $result) {
      if ($result instanceof UserInterface) {
        $account = $result;
        break;
      }
    }

    if ($account) {
      // An existing account was found. Save user claims.
      if ($this->configFactory->get('openid_connect.settings')->get('always_save_userinfo')) {
        $context = [
          'tokens' => $tokens,
          'plugin_id' => $client->getPluginId(),
          'user_data' => $user_data,
          'userinfo' => $userinfo,
          'sub' => $sub,
          'is_new' => FALSE,
        ];
        $this->saveUserinfo($account, $context);
      }
    }
    else {
      // Check whether the e-mail address is valid.
      if (!$this->emailValidator->isValid($userinfo['email'])) {
        $error_context = $common_error_context + ['@email' => $userinfo['email']];
        $this->setAuthorizationState(
          self::ERROR_INVALID_EMAIL,
          $this->t('Logging in with @provider could not be completed due to an invalid email address: @email.', $error_context)
        );
        return FALSE;
      }

      // Check whether there is an e-mail address conflict.
      $accounts = $this->userStorage->loadByProperties([
        'mail' => $userinfo['email'],
      ]);
      if ($accounts) {
        $account = reset($accounts);
        $connect_existing_users = $this->configFactory->get('openid_connect.settings')
          ->get('connect_existing_users');
        if ($connect_existing_users) {
          // Connect existing user account with this sub.
          $this->authmap->createAssociation($account, $client->getPluginId(), $sub);
        }
        else {
          $this->setAuthorizationState(
            self::ERROR_EMAIL_TAKEN,
            $this->t('The e-mail address is already taken: @email', ['@email' => $userinfo['email']])
          );
          return FALSE;
        }
      }

      // Check Drupal user register settings before saving.
      $register = $this->configFactory->get('user.settings')
        ->get('register');
      // Respect possible override from OpenID-Connect settings.
      $register_override = $this->configFactory->get('openid_connect.settings')
        ->get('override_registration_settings');
      if ($register === USER_REGISTER_ADMINISTRATORS_ONLY && $register_override) {
        $register = USER_REGISTER_VISITORS;
      }

      if (empty($account)) {
        switch ($register) {
          case USER_REGISTER_ADMINISTRATORS_ONLY:
            // Deny user registration.
            $this->setAuthorizationState(
              self::ERROR_REGISTRATION_RESTRICTED,
              $this->t('Only administrators can register new accounts.')
            );
            return FALSE;

          case USER_REGISTER_VISITORS:
            // Create a new account if register settings is set to visitors or
            // override is active.
            $account = $this->createUser($sub, $userinfo, $client->getPluginId(), 1);
            break;

          case USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL:
            // Create a new account and inform the user of the pending approval.
            $account = $this->createUser($sub, $userinfo, $client->getPluginId(), 0);
            $this->messenger->addMessage($this->t('Thank you for applying for an account. Your account is currently pending approval by the site administrator.'));
            break;
        }
      }

      // Store the newly created account.
      $context = [
        'tokens' => $tokens,
        'plugin_id' => $client->getPluginId(),
        'user_data' => $user_data,
        'userinfo' => $userinfo,
        'sub' => $sub,
        'is_new' => TRUE,
      ];
      $this->saveUserinfo($account, $context);
      $this->authmap->createAssociation($account, $client->getPluginId(), $sub);
    }

    // Whether the user should not be logged in due to pending administrator
    // approval.
    if ($account->isBlocked()) {
      $this->setAuthorizationState(
        self::ERROR_USER_INACTIVE,
        $this->t('The username %name has not been activated or is blocked.', ['%name' => $account->getAccountName()])
      );
      return FALSE;
    }

    $this->loginUser($account);

    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
      'userinfo' => $userinfo,
      'sub' => $sub,
    ];
    $this->moduleHandler->invokeAll(
      'openid_connect_post_authorize',
      [
        $account,
        $context,
      ]
    );

    $this->setAuthorizationState(self::SUCCESSFULL_LOGIN);
    return TRUE;
  }

  /**
   * Connect the current user's account to an external provider.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface $client
   *   The client.
   * @param array $tokens
   *   The tokens as returned from
   *   OpenIDConnectClientInterface::retrieveTokens().
   *
   * @return bool
   *   TRUE on success, FALSE on failure.
   */
  public function connectCurrentUser(OpenIDConnectClientInterface $client, array $tokens) {
    if (!$this->currentUser->isAuthenticated()) {
      throw new \RuntimeException('User not logged in');
    }

    $this->setAuthorizationState(self::ATTEMPTING_AUTHORIZATION);

    $common_error_context = [
      '@provider' => $client->getPluginId(),
    ];

    /* @var \Drupal\openid_connect\Authmap $authmap */
    $user_data = $client->decodeIdToken($tokens['id_token']);
    $userinfo = $client->retrieveUserInfo($tokens['access_token']);

    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
    ];
    $this->moduleHandler->alter('openid_connect_userinfo', $userinfo, $context);

    $provider_param = [
      '@provider' => $client->getPluginId(),
    ];

    if ($userinfo && empty($userinfo['email'])) {
      $message = 'No e-mail address provided by @provider';
      $variables = $provider_param;
      $this->logger->error($message . ' (@code @error). Details: @details', $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_FAILED,
        $this->t('Connecting with @provider could not be completed due to an error.', $common_error_context)
      );
      return FALSE;
    }

    $sub = $this->extractSub($user_data, $userinfo, $client->byPassSubValidation());
    if (empty($sub)) {
      $message = 'No "sub" found from @provider';
      $variables = $provider_param;
      $this->logger->error($message . ' (@code @error). Details: @details', $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_FAILED,
        $this->t('Connecting with @provider could not be completed due to an error.', $common_error_context)
      );
      return FALSE;
    }

    /* @var \Drupal\user\UserInterface $account */
    $account = $this->authmap->userLoadBySub($sub, $client->getPluginId());
    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
      'userinfo' => $userinfo,
      'sub' => $sub,
    ];
    $results = $this->moduleHandler->invokeAll('openid_connect_pre_authorize', [
      $account,
      $context,
    ]);

    // Deny access if any module returns FALSE.
    if (in_array(FALSE, $results, TRUE)) {
      $message = 'Login denied for @email via pre-authorize hook.';
      $variables = ['@email' => $userinfo['email']];
      $this->logger->error($message, $variables);
      $this->setAuthorizationState(
        self::ERROR_AUTHORIZATION_DENIED,
        $this->t('Connecting with @provider was denied.', $common_error_context)
      );
      return FALSE;
    }

    // If any module returns an account, set local $account to that.
    foreach ($results as $result) {
      if ($result instanceof UserInterface) {
        $account = $result;
        break;
      }
    }

    if ($account && $account->id() !== $this->currentUser->id()) {
      $this->setAuthorizationState(
        self::ERROR_ANOTHER_USER_CONNECTED,
        $this->t('Another user is already connected to this @provider account.', $common_error_context)
      );
      return FALSE;
    }

    if (!$account) {
      $account = $this->userStorage->load($this->currentUser->id());
      $this->authmap->createAssociation($account, $client->getPluginId(), $sub);
    }

    $always_save_userinfo = $this->configFactory->get('openid_connect.settings')->get('always_save_userinfo');
    if ($always_save_userinfo) {
      $context = [
        'tokens' => $tokens,
        'plugin_id' => $client->getPluginId(),
        'user_data' => $user_data,
        'userinfo' => $userinfo,
        'sub' => $sub,
      ];
      $this->saveUserinfo($account, $context);
    }

    $context = [
      'tokens' => $tokens,
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
      'userinfo' => $userinfo,
      'sub' => $sub,
    ];
    $this->moduleHandler->invokeAll(
      'openid_connect_post_authorize',
      [
        $account,
        $context,
      ]
    );

    $this->setAuthorizationState(self::SUCCESSFULL_CONNECTION);
    return TRUE;
  }

  /**
   * Get a user account from an authorization.
   *
   * Used for tasks common to completeAuthorization and connectCurrentUser.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientInterface $client
   *   The client.
   *
   * @return \Drupal\user\UserInterface|null
   *   A user account or NULL. NULL will be returned if there was a problem
   *   with the authorization, the authorization was denied via
   *   hook_openid_connect_pre_authorize, or if no existing user was found.
   *   The user account may be one found by a sub match or one provided
   *   by hook_openid_connect_pre_authorize.
   */
  protected function validateAuthorization(OpenIDConnectStatefulClientInterface $client) : ?UserInterface {
    $this->setAuthorizationState(self::ATTEMPTING_AUTHORIZATION);
    $common_error_context = [
      '@provider' => $client->getPluginId(),
    ];
    if (!$client->validateIdToken()) {
      $this->logger->error('Client @provider failed to get a valid ID Token.', $common_error_context);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
      return NULL;
    }
    // Id token is valid, so we can get claims from it.
    $user_data = $client->getDecodedIdToken();
    if (!$client->fetchUserInfo()) {
      $this->logger->error('Client @provider failed to retrieve a valid Userinfo response.', $common_error_context);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
      return NULL;
    }
    // Clients should validate sub while fetching user info, but double check.
    try {
      if (!$client->validateSub()) {
        $this->logger->error('Client @provider failed to retrieve a valid Userinfo response.', $common_error_context);
        $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
        return NULL;
      }
    }
    catch (Exception $e) {
      $error_context = $common_error_context + ['@error_details' => $e->getMessage()];
      $this->logger->error('Client @provider failed to perform sub validation as part of fetching userinfo. Details: @error_details', $error_context);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
      return NULL;
    }

    // Now we should have valid userinfo, but first allow the client a chance
    // to take into account its own possible user mappings.
    /* @var \Drupal\user\UserInterface|null $account */
    $account = $client->findUser($this->authmap);
    $userinfo = $client->getUserInfo();

    // Handle hook_openid_connect_userinfo.
    $hook_userinfo_context = [
      'tokens' => $client->getTokens(),
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
    ];
    $this->moduleHandler->alter('openid_connect_userinfo', $userinfo, $hook_userinfo_context);
    // Any changes must be passed back to the client, but allow the client to
    // have final say in the matter.
    $client->updateUserInfo($userinfo);
    /* @var \Drupal\user\UserInterface|null $account */
    $account = $client->findUser($this->authmap);
    $userinfo = $client->getUserInfo();

    // By now we can expect an email address.
    if ($userinfo && empty($userinfo['email'])) {
      $message = 'No e-mail address provided by @provider';
      $this->logger->error('No e-mail address provided by @provider', $common_error_context);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
      return NULL;
    }

    // No need to validate sub again for trusting the response, but it should
    // still not be empty.
    $sub = $client->getSub();
    if (empty($sub)) {
      $this->logger->error('No "sub" found from @provider', $common_error_context);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_FAILED);
      return NULL;
    }

    // Use the account provided by the client if it provided one.
    if (empty($account)) {
      /* @var \Drupal\user\UserInterface|null $account */
      $account = $this->authmap->userLoadBySub($sub, $client->getPluginId());
    }
    $hook_pre_authorize_context = [
      'tokens' => $client->getTokens(),
      'plugin_id' => $client->getPluginId(),
      'user_data' => $user_data,
      'userinfo' => $userinfo,
      'sub' => $sub,
    ];
    $results = $this->moduleHandler->invokeAll('openid_connect_pre_authorize', [
      $account,
      $hook_pre_authorize_context,
    ]);

    // Deny access if any module returns FALSE.
    if (in_array(FALSE, $results, TRUE)) {
      $message = 'Login denied for @email via pre-authorize hook.';
      $variables = ['@email' => $userinfo['email']];
      $this->logger->error($message, $variables);
      $this->setAuthorizationState(self::ERROR_AUTHORIZATION_DENIED);
      return NULL;
    }

    // If any module returns an account, set local $account to that.
    foreach ($results as $result) {
      if ($result instanceof UserInterface) {
        $account = $result;
        break;
      }
    }

    if ($account instanceof UserInterface) {
      return $account;
    }
    return NULL;
  }

  /**
   * Find whether a user is allowed to change the own password.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   Optional: Account to check the access for.
   *   Defaults to the currently logged-in user.
   *
   * @return bool
   *   TRUE if access is granted, FALSE otherwise.
   */
  public function hasSetPasswordAccess(AccountInterface $account = NULL) {
    if (empty($account)) {
      $account = $this->currentUser;
    }

    if ($account->hasPermission('openid connect set own password')) {
      return TRUE;
    }

    $connected_accounts = $this->authmap->getConnectedAccounts($account);

    return empty($connected_accounts);
  }

  /**
   * Ensure a client is stateful by wrapping it in one if it is not one already.
   *
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientInterface $client
   *   A client plugin.
   * @param array $tokens
   *   Tokens as returned from
   *   OpenIDConnectClientInterface::retrieveTokens().
   *
   * @return \Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientInterface
   *   The client plugin, if it was an instance of
   *   OpenIDConnectStatefulClientInterface, or an
   *   OpenIDConnectStatelessClientWrapper if it was not.
   */
  protected function getStatefulClient(OpenIDConnectClientInterface $client, array $tokens) : OpenIDConnectStatefulClientInterface {
    if ($client instanceof OpenIDConnectStatefulClientInterface) {
      return $client;
    }
    $configuration = $this->configFactory->get('openid_connect.settings.stateless_client_wrapper')->get();
    /** @var \Drupal\openid_connect\Plugin\OpenIDConnectStatelessClientWrapper $wrapper_client */
    $wrapper_client = $this->pluginManager->createInstance(
      'stateless_client_wrapper',
      $configuration
    );
    $wrapper_client->initializeWithTokens($client, $tokens);
    return $wrapper_client;
  }

  /**
   * Create a user indicating sub-id and login provider.
   *
   * @param string $sub
   *   The subject identifier.
   * @param array $userinfo
   *   The user claims, containing at least 'email'.
   * @param string $client_name
   *   The machine name of the client.
   * @param int $status
   *   The initial user status.
   *
   * @return \Drupal\user\UserInterface|false
   *   The user object or FALSE on failure.
   */
  public function createUser($sub, array $userinfo, $client_name, $status = 1) {
    /** @var \Drupal\user\UserInterface $account */
    $account = $this->userStorage->create([
      'name' => $this->generateUsername($sub, $userinfo, $client_name),
      'pass' => user_password(),
      'mail' => $userinfo['email'],
      'init' => $userinfo['email'],
      'status' => $status,
      'openid_connect_client' => $client_name,
      'openid_connect_sub' => $sub,
    ]);
    $account->save();

    return $account;
  }

  /**
   * Log in a user.
   *
   * @param \Drupal\user\UserInterface $account
   *   The user account to login.
   */
  protected function loginUser(UserInterface $account) {
    user_login_finalize($account);
  }

  /**
   * Generate a username for a new account.
   *
   * @param string $sub
   *   The subject identifier.
   * @param array $userinfo
   *   The user claims.
   * @param string $client_name
   *   The client identifier.
   *
   * @return string
   *   A unique username.
   */
  public function generateUsername($sub, array $userinfo, $client_name) {
    $name = 'oidc_' . $client_name . '_' . md5($sub);
    $candidates = ['preferred_username', 'name'];
    foreach ($candidates as $candidate) {
      if (!empty($userinfo[$candidate])) {
        $name = trim($userinfo[$candidate]);
        break;
      }
    }

    // Ensure there are no duplicates.
    for ($original = $name, $i = 1; $this->usernameExists($name); $i++) {
      $name = $original . '_' . $i;
    }

    return $name;
  }

  /**
   * Check if a user name already exists.
   *
   * @param string $name
   *   A name to test.
   *
   * @return bool
   *   TRUE if a user exists with the given name, FALSE otherwise.
   */
  public function usernameExists($name) {
    $users = $this->userStorage->loadByProperties([
      'name' => $name,
    ]);

    return (bool) $users;
  }

  /**
   * Save user profile information into a user account.
   *
   * @param \Drupal\user\UserInterface $account
   *   An user account object.
   * @param array $context
   *   An associative array with context information:
   *   - tokens:         An array of tokens.
   *   - user_data:      An array of user and session data.
   *   - userinfo:       An array of user information.
   *   - plugin_id:      The plugin identifier.
   *   - sub:            The remote user identifier.
   */
  public function saveUserinfo(UserInterface $account, array $context) {
    $userinfo = $context['userinfo'];
    $properties = $this->entityFieldManager->getFieldDefinitions('user', 'user');
    $properties_skip = $this->userPropertiesIgnore($context);
    foreach ($properties as $property_name => $property) {
      if (isset($properties_skip[$property_name])) {
        continue;
      }

      $userinfo_mappings = $this->configFactory->get('openid_connect.settings')
        ->get('userinfo_mappings');
      if (isset($userinfo_mappings[$property_name])) {
        $claim = $userinfo_mappings[$property_name];

        if ($claim && isset($userinfo[$claim])) {
          $claim_value = $userinfo[$claim];
          $property_type = $property->getType();

          $claim_context = $context + [
            'claim' => $claim,
            'property_name' => $property_name,
            'property_type' => $property_type,
            'userinfo_mappings' => $userinfo_mappings,
          ];
          $this->moduleHandler->alter(
            'openid_connect_userinfo_claim',
            $claim_value,
            $claim_context
          );

          // Set the user property, while ignoring exceptions from invalid
          // values.
          try {
            switch ($property_type) {
              case 'string':
              case 'string_long':
              case 'datetime':
                $account->set($property_name, $claim_value);
                break;

              case 'image':
                // Create file object from remote URL.
                $basename = explode('?', drupal_basename($claim_value))[0];
                $data = file_get_contents($claim_value);
                $file = file_save_data(
                  $data,
                  'public://user-picture-' . $account->id() . '-' . $basename,
                  FILE_EXISTS_RENAME
                );

                // Cleanup the old file.
                if ($file) {
                  $old_file = $account->$property_name->entity;
                  if ($old_file) {
                    $old_file->delete();
                  }
                }

                $account->set(
                  $property_name,
                  [
                    'target_id' => $file->id(),
                  ]
                );
                break;

              default:
                $this->logger->error(
                  'Could not save user info, property type not implemented: %property_type',
                  [
                    '%property_type' => $property_type,
                  ]
                );
                break;

            }
          }
          // Catch the error if the field does not exist.
          catch (\InvalidArgumentException $e) {
            $this->logger->error($e->getMessage());
          }
        }
      }
    }

    // Save the display name additionally in the user account 'data', for
    // use in openid_connect_username_alter().
    if (isset($userinfo['name'])) {
      $this->userData->set('openid_connect', $account->id(), 'oidc_name', $userinfo['name']);
    }

    // Allow other modules to add additional user information.
    $this->moduleHandler->invokeAll('openid_connect_userinfo_save', [
      $account,
      $context,
    ]);

    $account->save();
  }

}
