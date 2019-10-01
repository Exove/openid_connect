<?php

namespace Drupal\openid_connect\Plugin\OpenIDConnectClient;

use Drupal\openid_connect\Plugin\OpenIDConnectStatefulClientBase;

/**
 * Finnish Trust Network OpenID Connect client.
 *
 * Used to log in using using the Finnish Trust Network.
 *
 * @OpenIDConnectClient(
 *   id = "ftn",
 *   label = @Translation("Finnish Trust Network")
 * )
 */
class OpenIDConnectFtnClient extends OpenIDConnectStatefulClientBase {

}
