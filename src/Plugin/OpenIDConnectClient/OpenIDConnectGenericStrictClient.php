<?php

namespace Drupal\openid_connect\Plugin\OpenIDConnectClient;

use Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientBase;

/**
 * Generic strict stateful OpenID Connect client.
 *
 * Used to log in using any OpenID Connect compliant Identity Provider.
 *
 * @OpenIDConnectClient(
 *   id = "generic_strict",
 *   label = @Translation("Generic Strict")
 * )
 */
class OpenIDConnectGenericStrictClient extends OpenIDConnectStatefulClientBase {

}
