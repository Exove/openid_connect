<?php

namespace Drupal\openid_connect;

use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;

/**
 * Service providing helpers for working with Json Web Tokens (JWT).
 */
class OpenIDConnectJwtHelper {

  /**
   * Logger for this service.
   *
   * @var Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * Signature Algorithm Manager Factory.
   *
   * @var \Jose\Component\Core\AlgorithmManagerFactory
   */
  protected $signatureAlgorithmManagerFactory;

  /**
   * Key Encryption Algorithm Manager Factory.
   *
   * @var \Jose\Component\Core\AlgorithmManagerFactory
   */
  protected $keyEncryptionAlgorithmManagerFactory;

  /**
   * Content Encryption Algorithm Manager Factory.
   *
   * @var \Jose\Component\Core\AlgorithmManagerFactory
   */
  protected $contentEncryptionAlgorithmManagerFactory;

  /**
   * Header Checker Manager Factory.
   *
   * @var \Jose\Component\Checker\HeaderCheckerManagerFactory
   */
  protected $headerCheckerManagerFactory;

  /**
   * JWE Serializer Manager.
   *
   * @var \Jose\Component\Encryption\Serializer\JWESerializerManager
   */
  protected $jweSerializerManager;

  /**
   * JWS Serializer Manager.
   *
   * @var \Jose\Component\Signature\Serializer\JWSSerializerManager
   */
  protected $jwsSerializerManager;

  /**
   * Supported algorithms in the format name => class name.
   *
   * @var array
   */
  protected $signatureAlgorithms = [
    'ES256' => 'ES256',
    'ES384' => 'ES384',
    'ES512' => 'ES512',
    'EdDSA' => 'EdDSA',
    'HS512' => 'HS512',
    'HS384' => 'HS384',
    'HS256' => 'HS256',
    'none' => 'none',
    'RS384' => 'RS384',
    'PS256' => 'PS256',
    'PS384' => 'PS384',
    'RS256' => 'RS256',
    'RS512' => 'RS512',
    'PS512' => 'PS512',
  ];

  /**
   * Supported key encryption algorithms in the format name => class name.
   *
   * @var array
   */
  protected $keyEncryptionAlgorithms = [
    'A256GCMKW' => 'A256GCMKW',
    'A128GCMKW' => 'A128GCMKW',
    'A192GCMKW' => 'A192GCMKW',
    'A256KW' => 'A256KW',
    'A192KW' => 'A192KW',
    'A128KW' => 'A128KW',
    'dir' => 'Dir',
    'ECDH-ES+A256KW' => 'ECDHESA256KW',
    'ECDH-ES' => 'ECDHES',
    'ECDH-ES+A192KW' => 'ECDHESA192KW',
    'ECDH-ES+A128KW' => 'ECDHESA128KW',
    'PBES2-HS512+A256KW' => 'PBES2HS512A256KW',
    'PBES2-HS256+A128KW' => 'PBES2HS256A128KW',
    'PBES2-HS384+A192KW' => 'PBES2HS384A192KW',
    'RSA1_5' => 'RSA15',
    'RSA-OAEP' => 'RSAOAEP',
    'RSA-OAEP-256' => 'RSAOAEP256',
  ];

  /**
   * Supported content encryption algorithms in the format name => class name.
   *
   * @var array
   */
  protected $contentEncryptionAlgorithms = [
    'A192CBC-HS384' => 'A192CBCHS384',
    'A256CBC-HS512' => 'A256CBCHS512',
    'A128CBC-HS256' => 'A128CBCHS256',
    'A128GCM' => 'A128GCM',
    'A256GCM' => 'A256GCM',
    'A192GCM' => 'A192GCM',
  ];

  /**
   * Constants for namespaces for algorithms.
   */
  const NAMESPACE_FOR_SIGNATURE_ALGORITHMS = '\Jose\Component\Signature\Algorithm';
  const NAMESPACE_FOR_KEY_ENCRYPTION_ALGORITHMS = '\Jose\Component\Encryption\Algorithm\KeyEncryption';
  const NAMESPACE_FOR_CONTENT_ENCRYPTION_ALGORITHMS = '\Jose\Component\Encryption\Algorithm\ContentEncryption';

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   A logger channel factory instance.
   */
  public function __construct(LoggerChannelFactoryInterface $logger_factory) {
    $this->logger = $logger_factory->get('openid_connect.jwt_helper');
    $this->signatureAlgorithmManagerFactory = new AlgorithmManagerFactory();
    $this->keyEncryptionAlgorithmManagerFactory = new AlgorithmManagerFactory();
    $this->contentEncryptionAlgorithmManagerFactory = new AlgorithmManagerFactory();
    $this->jwsSerializerManagerFactory = new JWSSerializerManagerFactory();
    $this->jwsSerializerManagerFactory->add(new JwsCompactSerializer());
    $this->jweSerializerManagerFactory = new JWESerializerManagerFactory();
    $this->jweSerializerManagerFactory->add(new JweCompactSerializer());
  }

  /**
   * Check if an algorithm is supported for signatures by name.
   *
   * @param string $algorithm
   *   Name of algorithm.
   *
   * @return bool
   *   Whether the algorithm is supported for signatures.
   */
  public function isAlgorithmSupportedForSignatures(string $algorithm) : bool {
    return isset($this->signatureAlgorithms[$algorithm]);
  }

  /**
   * Check if an algorithm is supported for key encryption by name.
   *
   * @param string $algorithm
   *   Name of algorithm.
   *
   * @return bool
   *   Whether the algorithm is supported for key encryption.
   */
  public function isAlgorithmSupportedForKeyEncryption(string $algorithm) : bool {
    return isset($this->keyEncryptionAlgorithms[$algorithm]);
  }

  /**
   * Check if an algorithm is supported for content encryption by name.
   *
   * @param string $algorithm
   *   Name of algorithm.
   *
   * @return bool
   *   Whether the algorithm is supported for content encryption.
   */
  public function isAlgorithmSupportedForContentEncryption(string $algorithm) : bool {
    return isset($this->contentEncryptionAlgorithms[$algorithm]);
  }

  /**
   * Get a SignatureAlgorithm instance by name of the algorithm.
   *
   * @param string $algorithm
   *   Name of the algorithm.
   *
   * @return \Jose\Component\Signature\Algorithm\SignatureAlgorithm|null
   *   A class implementing the requested algorithm.
   */
  public function getSignatureAlgorithmInstance(string $algorithm) : ?SignatureAlgorithm {
    if (!$this->isAlgorithmSupportedForSignatures($algorithm)) {
      return NULL;
    }
    $algorithm_class = self::NAMESPACE_FOR_SIGNATURE_ALGORITHMS . '\\' . $this->signatureAlgorithms[$algorithm];
    $algorithm_instance = new $algorithm_class();
    // The name of the algorithm instance should match the requested name.
    // If the requested name and the name of the instance do not point to
    // the same class(the requested name is an alias), something is probably
    // wrong, so abort.
    $class_by_request_name = $this->signatureAlgorithms[$algorithm];
    $class_by_result_name  = $this->signatureAlgorithms[$algorithm_instance->name()];
    if ($class_by_request_name !== $class_by_result_name) {
      $this->logger->error('Algorithm name @algorithm does not match supported algorithm mapping.', ['@algorithm' => $algorithm]);
      return NULL;
    }
    return $algorithm_instance;
  }

  /**
   * Get a KeyEncryptionAlgorithm instance by name of the algorithm.
   *
   * @param string $algorithm
   *   Name of the algorithm.
   *
   * @return \Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm|null
   *   A class implementing the requested algorithm.
   */
  public function getKeyEncryptionAlgorithmInstance(string $algorithm) : ?KeyEncryptionAlgorithm {
    if (!$this->isAlgorithmSupportedForKeyEncryption($algorithm)) {
      return NULL;
    }
    $algorithm_class = self::NAMESPACE_FOR_KEY_ENCRYPTION_ALGORITHMS . '\\' . $this->keyEncryptionAlgorithms[$algorithm];
    $algorithm_instance = new $algorithm_class();
    // The name of the algorithm instance should match the requested name.
    // If the requested name and the name of the instance do not point to
    // the same class(the requested name is an alias), something is probably
    // wrong, so abort.
    $class_by_request_name = $this->keyEncryptionAlgorithms[$algorithm];
    $class_by_result_name  = $this->keyEncryptionAlgorithms[$algorithm_instance->name()];
    if ($class_by_request_name !== $class_by_result_name) {
      $this->logger->error('Algorithm name @algorithm does not match supported algorithm mapping.', ['@algorithm' => $algorithm]);
      return NULL;
    }
    return $algorithm_instance;
  }

  /**
   * Get a ContentEncryptionAlgorithm instance by name of the algorithm.
   *
   * @param string $algorithm
   *   Name of the algorithm.
   *
   * @return \Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm|null
   *   A class implementing the requested algorithm.
   */
  public function getContentEncryptionAlgorithmInstance(string $algorithm) : ?ContentEncryptionAlgorithm {
    if (!$this->isAlgorithmSupportedForContentEncryption($algorithm)) {
      return NULL;
    }
    $algorithm_class = self::NAMESPACE_FOR_CONTENT_ENCRYPTION_ALGORITHMS . '\\' . $this->contentEncryptionAlgorithms[$algorithm];
    $algorithm_instance = new $algorithm_class();
    // The name of the algorithm instance should match the requested name.
    // If the requested name and the name of the instance do not point to
    // the same class(the requested name is an alias), something is probably
    // wrong, so abort.
    $class_by_request_name = $this->contentEncryptionAlgorithms[$algorithm];
    $class_by_result_name  = $this->contentEncryptionAlgorithms[$algorithm_instance->name()];
    if ($class_by_request_name !== $class_by_result_name) {
      $this->logger->error('Algorithm name @algorithm does not match supported algorithm mapping.', ['@algorithm' => $algorithm]);
      return NULL;
    }
    return $algorithm_instance;
  }

  /**
   * Filter unsupported signature algorithms from a list of algorithms.
   *
   * @param array $algorithms
   *   An array of algorithm names.
   *
   * @return array
   *   An array of supported algorithms. May be empty if none were found.
   */
  public function filterUnsupportedSignatureAlgorithms(array $algorithms) : array {
    $supported_algorithms = [];
    foreach ($algorithms as $algorithm) {
      if ($this->isAlgorithmSupportedForSignatures($algorithm)) {
        $supported_algorithms[] = $algorithm;
      }
      else {
        $this->logger->warning('Algorithm @algorithm not supported for signatures.');
      }
    }
    return $supported_algorithms;
  }

  /**
   * Filter unsupported key encryption algorithms from a list of algorithms.
   *
   * @param array $algorithms
   *   An array of algorithm names.
   *
   * @return array
   *   An array of supported algorithms. May be empty if none were found.
   */
  public function filterUnsupportedKeyEncryptionAlgorithms(array $algorithms) : array {
    $supported_algorithms = [];
    foreach ($algorithms as $algorithm) {
      if ($this->isAlgorithmSupportedForKeyEncryption($algorithm)) {
        $supported_algorithms[] = $algorithm;
      }
      else {
        $this->logger->warning('Algorithm @algorithm not supported for key encryption.');
      }
    }
    return $supported_algorithms;
  }

  /**
   * Filter unsupported content encryption algorithms from a list of algorithms.
   *
   * @param array $algorithms
   *   An array of algorithm names.
   *
   * @return array
   *   An array of supported algorithms. May be empty if none were found.
   */
  public function filterUnsupportedContentEncryptionAlgorithms(array $algorithms) : array {
    $supported_algorithms = [];
    foreach ($algorithms as $algorithm) {
      if ($this->isAlgorithmSupportedForContentEncryption($algorithm)) {
        $supported_algorithms[] = $algorithm;
      }
      else {
        $this->logger->warning('Algorithm @algorithm not supported for content encryption.');
      }
    }
    return $supported_algorithms;
  }

  /**
   * Get an Algorithm Manager with the requested signature algorithms.
   *
   * @param array|null $algorithms
   *   An array of algorithm names. Unsupported ones are ignored.
   *   If the argument is empty, load all supported algorithms.
   *
   * @return \Jose\Component\Core\AlgorithmManager|null
   *   An Algorithm Manager containing the requested signature algorithms.
   *   Unrecognized algorithms are ignored. NULL is returned if none of the
   *   algorithms were supported.
   */
  public function getSignatureAlgorithmManager(?array $algorithms = []) : ?AlgorithmManager {
    if (empty($algorithms)) {
      $algorithms = array_keys($this->signatureAlgorithms);
    }
    $supported_algorithms = $this->filterUnsupportedSignatureAlgorithms($algorithms);
    $successfully_loaded_algorithms = [];
    $already_loaded = $this->signatureAlgorithmManagerFactory->aliases();
    foreach ($supported_algorithms as $algorithm) {
      if (in_array($algorithm, $already_loaded)) {
        $successfully_loaded_algorithms[] = $algorithm;
      }
      else {
        $algorithm_instance = $this->getSignatureAlgorithmInstance($algorithm);
        if (!empty($algorithm_instance)) {
          $this->signatureAlgorithmManagerFactory->add(
            $algorithm,
            $algorithm_instance
          );
          $successfully_loaded_algorithms[] = $algorithm;
        }
      }
    }
    if (empty($successfully_loaded_algorithms)) {
      $this->logger->error('Failed to get an algorithm manager for signatures because none of the requested algorithms were supported.');
      return NULL;
    }
    return $this->signatureAlgorithmManagerFactory->create($successfully_loaded_algorithms);
  }

  /**
   * Get an Algorithm Manager with the requested key encryption algorithms.
   *
   * @param array|null $algorithms
   *   An array of algorithm names. Unsupported ones are ignored.
   *   If the argument is empty, load all supported algorithms.
   *
   * @return \Jose\Component\Core\AlgorithmManager|null
   *   An Algorithm Manager containing the requested key encryption algorithms.
   *   Unrecognized algorithms are ignored. NULL is returned if none of the
   *   algorithms were supported.
   */
  public function getKeyEncryptionAlgorithmManager(?array $algorithms = []) : ?AlgorithmManager {
    if (empty($algorithms)) {
      $algorithms = array_keys($this->keyEncryptionAlgorithms);
    }
    $supported_algorithms = $this->filterUnsupportedKeyEncryptionAlgorithms($algorithms);
    $successfully_loaded_algorithms = [];
    $already_loaded = $this->keyEncryptionAlgorithmManagerFactory->aliases();
    foreach ($supported_algorithms as $algorithm) {
      if (in_array($algorithm, $already_loaded)) {
        $successfully_loaded_algorithms[] = $algorithm;
      }
      else {
        $algorithm_instance = $this->getKeyEncryptionAlgorithmInstance($algorithm);
        if (!empty($algorithm_instance)) {
          $this->keyEncryptionAlgorithmManagerFactory->add(
            $algorithm,
            $algorithm_instance
          );
          $successfully_loaded_algorithms[] = $algorithm;
        }
      }
    }
    if (empty($successfully_loaded_algorithms)) {
      $this->logger->error('Failed to get an algorithm manager for key encryption because none of the requested algorithms were supported.');
      return NULL;
    }
    return $this->keyEncryptionAlgorithmManagerFactory->create($successfully_loaded_algorithms);
  }

  /**
   * Get an Algorithm Manager with the requested content encryption algorithms.
   *
   * @param array|null $algorithms
   *   An array of algorithm names. Unsupported ones are ignored.
   *   If the argument is empty, load all supported algorithms.
   *
   * @return \Jose\Component\Core\AlgorithmManager|null
   *   An Algorithm Manager containing the requested content encryption
   *   algorithms. Unrecognized algorithms are ignored. NULL is returned if
   *   none of the algorithms were supported.
   */
  public function getContentEncryptionAlgorithmManager(?array $algorithms = []) : ?AlgorithmManager {
    if (empty($algorithms)) {
      $algorithms = array_keys($this->contentEncryptionAlgorithms);
    }
    $supported_algorithms = $this->filterUnsupportedContentEncryptionAlgorithms($algorithms);
    $successfully_loaded_algorithms = [];
    $already_loaded = $this->contentEncryptionAlgorithmManagerFactory->aliases();
    foreach ($supported_algorithms as $algorithm) {
      if (in_array($algorithm, $already_loaded)) {
        $successfully_loaded_algorithms[] = $algorithm;
      }
      else {
        $algorithm_instance = $this->getContentEncryptionAlgorithmInstance($algorithm);
        if (!empty($algorithm_instance)) {
          $this->contentEncryptionAlgorithmManagerFactory->add(
            $algorithm,
            $algorithm_instance
          );
          $successfully_loaded_algorithms[] = $algorithm;
        }
      }
    }
    if (empty($successfully_loaded_algorithms)) {
      $this->logger->error('Failed to get an algorithm manager for content encryption because none of the requested algorithms were supported.');
      return NULL;
    }
    return $this->contentEncryptionAlgorithmManagerFactory->create($successfully_loaded_algorithms);
  }

  /**
   * Get a compression method manager with the requested methods.
   *
   * Currently only supports Deflate.
   *
   * @param array|null $compression_methods
   *   An array of method names. Omit to get all supported methods.
   *
   * @return \Jose\Component\Encryption\Compression\CompressionMethodManager|null
   *   A compression method manager with the requested methods. Unrecognized
   *   algorithms are ignored. NULL is returned if none of the requested
   *   methods were supported.
   *
   * @todo Actually provide the requested methods instead of just Deflate.
   */
  public function getCompressionMethodManager(?array $compression_methods = []) : ?CompressionMethodManager {
    return new CompressionMethodManager([
      new Deflate(),
    ]);
  }

  /**
   * Get a Header Checker Manager.
   *
   * A Header Checker Manager always does some sanity checks for the headers
   * of a JWE or JWS, but may contain additional restrictions. Note that these
   * restrictions only apply if the header is present.
   *
   * There is a bug in web-token/jwt-checker which prevents iat, exp and nbf
   * checkers from working as header checkers. The fix is in the 2.1 branch,
   * but not yet released.
   *
   * @param array|null $algorithms
   *   An array of signature and/or key encryption algorithm names to accept.
   *   No restrictions by default.
   * @param array|null $issuers
   *   An array of issuer identifiers (iss) to accept.
   *   No restrictions by default.
   * @param string|null $audience
   *   An acceptable audience (aud). No restrictions by default.
   * @param bool|null $check_iat
   *   Require the token to have been issued in the past (iat), default TRUE.
   * @param bool|null $check_exp
   *   Require the token not to have expired (exp), default TRUE.
   * @param bool|null $check_nbf
   *   Require the token's "not before" value to be in the past, default TRUE.
   *
   * @return \Jose\Component\Checker\HeaderCheckerManager
   *   A Header Checker Manager that can perform the requested checks.
   *
   * @todo Document missing checker situation properly all over the place.
   */
  public function getHeaderCheckerManager(?array $algorithms = [], ?array $issuers = [], ?string $audience = NULL, ?bool $check_iat = TRUE, ?bool $check_exp = TRUE, ?bool $check_nbf = TRUE) : HeaderCheckerManager {
    if (empty($this->headerCheckerManagerFactory)) {
      $this->headerCheckerManagerFactory = new HeaderCheckerManagerFactory();
      $this->headerCheckerManagerFactory->addTokenTypeSupport(new JWETokenSupport());
      $this->headerCheckerManagerFactory->addTokenTypeSupport(new JWSTokenSupport());
    }
    // Aliases for checkers to include in this header checker manager.
    // @todo Don't create new checkers for ones that already exist?
    $aliases = [];
    if (!empty($algorithms)) {
      $algorithm_alias = implode(',', $algorithms);
      $this->headerCheckerManagerFactory->add($algorithm_alias, new AlgorithmChecker($algorithms));
      $aliases[] = $algorithm_alias;
    }
    if (!empty($issuers)) {
      $issuer_alias = implode(',', $issuers);
      $this->headerCheckerManagerFactory->add($issuer_alias, new IssuerChecker($issuers));
      $aliases[] = $issuer_alias;
    }
    if (!empty($audience)) {
      $this->headerCheckerManagerFactory->add($audience, new AudienceChecker($audience));
      $aliases[] = $audience;
    }
    if ($check_iat) {
      $checker = new IssuedAtChecker();
      if ($checker instanceof HeaderChecker) {
        $this->headerCheckerManagerFactory->add('iat', $checker);
        $aliases[] = 'iat';
      }
      else {
        $this->logger->error('Could not load @checker JWT Header Checker.', ['@checker' => 'Issued At (iat)']);
      }
    }
    if ($check_exp) {
      $checker = new ExpirationTimeChecker();
      if ($checker instanceof HeaderChecker) {
        $this->headerCheckerManagerFactory->add('exp', $checker);
        $aliases[] = 'exp';
      }
      else {
        $this->logger->error('Could not load @checker JWT Header Checker.', ['@checker' => 'Expires (exp)']);
      }
    }
    if ($check_nbf) {
      $checker = new NotBeforeChecker();
      if ($checker instanceof HeaderChecker) {
        $this->headerCheckerManagerFactory->add('nbf', $checker);
        $aliases[] = 'nbf';
      }
      else {
        $this->logger->error('Could not load @checker JWT Header Checker.', ['@checker' => 'Not Before (nbf)']);
      }
    }
    return $this->headerCheckerManagerFactory->create($aliases);
  }

  /**
   * Get a JWE Serializer Manager.
   *
   * @return \Jose\Component\Encryption\Serializer\JWESerializerManager
   *   A JWE Serializer Manager.
   */
  public function getJweSerializerManager() : JWESerializerManager {
    if (!$this->jweSerializerManager) {
      $this->jweSerializerManager = new JWESerializerManager([
        new JweCompactSerializer(),
      ]);
    }
    return $this->jweSerializerManager;
  }

  /**
   * Get a JWS Serializer Manager.
   *
   * @return \Jose\Component\Signature\Serializer\JWSSerializerManager
   *   A JWS Serializer Manager.
   */
  public function getJwsSerializerManager() : JWSSerializerManager {
    if (!$this->jwsSerializerManager) {
      $this->jwsSerializerManager = new JWSSerializerManager([
        new JwsCompactSerializer(),
      ]);
    }
    return $this->jwsSerializerManager;
  }

  /**
   * Serialize a JWE using compact serialization.
   *
   * @param \Jose\Component\Encryption\JWE $jwe
   *   The JWE to serialize.
   *
   * @return string
   *   The serialized JWE.
   */
  public function serializeJwe(JWE $jwe) : string {
    $serializer = new JweCompactSerializer();
    return $serializer->serialize($jwe);
  }

  /**
   * Unserialize a JWE using compact serialization.
   *
   * @param string $token
   *   The string to unserialize as a JWE.
   *
   * @return \Jose\Component\Encryption\JWE
   *   The resulting JWE.
   */
  public function unserializeJwe(string $token) : JWE {
    $serializer = new JweCompactSerializer();
    return $serializer->unserialize($token);
  }

  /**
   * Serialize a JWS using compact serialization.
   *
   * @param \Jose\Component\Signature\JWS $jws
   *   The JWS to serialize.
   *
   * @return string
   *   The serialized JWS.
   */
  public function serializeJws(JWS $jws) : string {
    $serializer = new JwsCompactSerializer();
    return $serializer->serialize($jws);
  }

  /**
   * Unserialize a JWS using compact serialization.
   *
   * @param string $token
   *   The string to unserialize as a JWS.
   *
   * @return \Jose\Component\Signature\JWS
   *   The resulting JWS.
   */
  public function unserializeJws(string $token) : JWS {
    $serializer = new JwsCompactSerializer();
    return $serializer->unserialize($token);
  }

  /**
   * Get a JWE builder supporting the given algorithms and methods.
   *
   * @param array $key_encryption_algorithms
   *   A list of key encryption algorithm names.
   * @param array $content_encryption_algorithms
   *   A list of content encryption algorithm names.
   * @param array|null $compression_methods
   *   An optional list of compression method names. Currently ignored, defaults
   *   to Deflate.
   *
   * @return \Jose\Component\Encryption\JWEBuilder|null
   *   A JWE builder supporting the requested algorithms. NULL is returned
   *   if all key encryption algorithms, all content encryption algorithms,
   *   or all compression methods were unsupported.
   */
  public function getJweBuilder(array $key_encryption_algorithms, array $content_encryption_algorithms, ?array $compression_methods = []) : ?JWEBuilder {
    $key_encryption_algorithm_manager = $this->getKeyEncryptionAlgorithmManager($key_encryption_algorithms);
    $content_encryption_algorithm_manager = $this->getContentEncryptionAlgorithmManager($content_encryption_algorithms);
    $compression_method_manager = $this->getCompressionMethodManager($compression_methods);
    if (empty($key_encryption_algorithm_manager) ||
        empty($content_encryption_algorithm_manager) ||
        empty($compression_method_manager)) {
      $this->logger->error('Failed to get a JWEBuilder due to requested algorithms being unsupported.');
      return NULL;
    }
    return new JWEBuilder(
      $key_encryption_algorithm_manager,
      $content_encryption_algorithm_manager,
      $compression_method_manager
    );
  }

  /**
   * Build a JWE.
   *
   * @param array $payload
   *   The payload.
   * @param \Jose\Component\Core\JWK $jwk
   *   A key to use for encryption.
   * @param string $content_encryption_algorithm
   *   Content encryption algorithm.
   * @param string|null $key_encryption_algorithm
   *   Content encryption algorithm. If omitted, the 'alg' parameter from the
   *   key will be used.
   * @param array|null $protected_header
   *   An optional protected header. If omitted, default header is:
   *     - 'alg' => from the key
   *     - 'enc' => the algorithm
   *     - 'typ' => 'JWE'
   *     - 'kid' => from the key, if set.
   *
   * @return string
   *   A JWE encrypted with the given key and algorithm, using the protected
   *   headers if given, or the default ones, serialized using compact
   *   serialization.
   *
   * @throws Exception
   *   Throws an exception on failure.
   */
  public function buildJwe(array $payload, JWK $jwk, string $content_encryption_algorithm, ?string $key_encryption_algorithm = NULL, ?array $protected_header = NULL) : string {
    try {
      $payload_json = json_encode($payload);
      if (empty($key_encryption_algorithm)) {
        // @todo If key doesn't have an alg, this will throw.
        $key_encryption_algorithm = $jwk->get('alg');
      }
      if (empty($protected_header)) {
        $protected_header = [
          'alg' => $key_encryption_algorithm,
          'enc' => $content_encryption_algorithm,
          'typ' => 'JWE',
        ];
        if ($jwk->has('kid')) {
          $protected_header['kid'] = $jwk->get('kid');
        }
      }
      $jweBuilder = $this->getJweBuilder([$key_encryption_algorithm], [$content_encryption_algorithm]);
      $jwe = $jweBuilder
        ->create()
        ->withPayload($payload_json)
        ->withSharedProtectedHeader($protected_header)
        ->addRecipient($jwk)
        ->build();
      $token = $this->serializeJwe($jwe);
      return $token;
    }
    catch (\Exception $e) {
      $this->logger->error('Failed to build a JWE. Details: @error_details', ['@error_details' => $e->getMessage()]);
      throw $e;
    }
  }

  /**
   * Get a JWE Decrypter with the given algorithms and compression methods.
   *
   * @param array|null $key_encryption_algorithms
   *   An array of key encryption algorithm names to support. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the decrypter.
   * @param array|null $content_encryption_algorithms
   *   An array of content encryption algorithm names. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the decrypter.
   * @param array|null $compression_methods
   *   An optional list of compression method names. Currently ignored, defaults
   *   to Deflate.
   *
   * @return \Jose\Component\Encryption\JWEDecrypter|null
   *   A JWE decrypter supporting the requested algorithms. NULL is returned
   *   if all key encryption algorithms, all content encryption algorithms,
   *   or all compression methods were unsupported.
   */
  public function getJweDecrypter(?array $key_encryption_algorithms = [], ?array $content_encryption_algorithms = [], ?array $compression_methods = []) : ?JWEDecrypter {
    $key_encryption_algorithm_manager = $this->getKeyEncryptionAlgorithmManager($key_encryption_algorithms);
    $content_encryption_algorithm_manager = $this->getContentEncryptionAlgorithmManager($content_encryption_algorithms);
    $compression_method_manager = $this->getCompressionMethodManager($compression_methods);
    if (empty($key_encryption_algorithm_manager) ||
        empty($content_encryption_algorithm_manager) ||
        empty($compression_method_manager)) {
      $this->logger->error('Failed to get a JWEDecrypter due to requested algorithms being unsupported.');
      return NULL;
    }
    return new JWEDecrypter(
      $key_encryption_algorithm_manager,
      $content_encryption_algorithm_manager,
      $compression_method_manager
    );
  }

  /**
   * Get a JWE Loader.
   *
   * @param array|null $key_encryption_algorithms
   *   An array of key encryption algorithm names to support. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $content_encryption_algorithms
   *   An array of content encryption algorithm names. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $accepted_key_encryption_algorithms
   *   An array of key encryption algorithms that are acceptable.
   *   No restrictions by default.
   * @param array|null $issuers
   *   An array of issuer identifiers (iss) to accept.
   *   No restrictions by default.
   * @param string|null $audience
   *   An acceptable audience (aud). No restrictions by default.
   * @param bool|null $check_iat
   *   Require the token to have been issued in the past (iat), default TRUE.
   * @param bool|null $check_exp
   *   Require the token not to have expired (exp), default TRUE.
   * @param bool|null $check_nbf
   *   Require the token's "not before" value to be in the past, default TRUE.
   * @param array|null $compression_methods
   *   An optional list of compression method names. Currently ignored, defaults
   *   to Deflate.
   *
   * @return \Jose\Component\Encryption\JWELoader|null
   *   A JWE Loader supporting the requested algorithms and requiring the
   *   requested validations. NULL is returned on failure, e.g. if only
   *   unsupported algorithms are requested.
   */
  public function getJweLoader(?array $key_encryption_algorithms = [], ?array $content_encryption_algorithms = [], ?array $accepted_key_encryption_algorithms = [], ?array $issuers = NULL, ?string $audience = NULL, ?bool $check_iat = TRUE, ?bool $check_exp = TRUE, ?bool $check_nbf = TRUE, ?array $compression_methods = []) : ?JWELoader {
    $serializer_manager = $this->getJweSerializerManager();
    $jwe_decrypter = $this->getJweDecrypter(
      $key_encryption_algorithms,
      $content_encryption_algorithms,
      $compression_methods
    );
    if (empty($jwe_decrypter)) {
      $this->logger->error('Failed to get a JWELoader due to failure to get a JWEDecrypter.');
      return NULL;
    }
    $header_checker_manager = $this->getHeaderCheckerManager(
      $accepted_key_encryption_algorithms,
      $issuers,
      $audience,
      $check_iat,
      $check_exp,
      $check_nbf
    );
    $jwe_loader = new JWELoader(
      $serializer_manager,
      $jwe_decrypter,
      $header_checker_manager
    );
    return $jwe_loader;
  }

  /**
   * Decrypt a JWE.
   *
   * @param string $token
   *   A serialized JWE Token.
   * @param \Jose\Component\Core\JWK $client_key
   *   The recipient key for decrypting the token.
   * @param array|null $key_encryption_algorithms
   *   An array of key encryption algorithm names to support. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $content_encryption_algorithms
   *   An array of content encryption algorithm names. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $accepted_key_encryption_algorithms
   *   An array of key encryption algorithms that are acceptable.
   *   No restrictions by default.
   * @param array|null $issuers
   *   An array of issuer identifiers (iss) to accept.
   *   No restrictions by default.
   * @param string|null $audience
   *   An acceptable audience (aud). No restrictions by default.
   * @param bool|null $check_iat
   *   Require the token to have been issued in the past (iat), default TRUE.
   * @param bool|null $check_exp
   *   Require the token not to have expired (exp), default TRUE.
   * @param bool|null $check_nbf
   *   Require the token's "not before" value to be in the past, default TRUE.
   * @param array|null $compression_methods
   *   An optional list of compression method names. Currently ignored, defaults
   *   to Deflate.
   *
   * @return string|null
   *   The decrypted payload, which should be either JSON in the case of an
   *   unsigned payload, or a serialized JWS token if signed. NULL is returned
   *   on failure.
   */
  public function decryptJwe(string $token, JWK $client_key, ?array $key_encryption_algorithms = [], ?array $content_encryption_algorithms = [], ?array $accepted_key_encryption_algorithms = [], ?array $issuers = NULL, ?string $audience = NULL, ?bool $check_iat = TRUE, ?bool $check_exp = TRUE, ?bool $check_nbf = TRUE, ?array $compression_methods = NULL) : ?string {
    $jwe_loader = $this->getJweLoader(
      $key_encryption_algorithms,
      $content_encryption_algorithms,
      $accepted_key_encryption_algorithms,
      $issuers,
      $audience,
      $check_iat,
      $check_exp,
      $check_nbf,
      $compression_methods
    );
    if (empty($jwe_loader)) {
      $this->logger->error('Failed to decrypt a JWE due to failure in getting a JWELoader');
      return NULL;
    }
    try {
      $recipient_index = 0;
      // This will throw on failure.
      /** @var \Jose\Component\Encryption\JWE $jwe */
      $jwe = $jwe_loader->loadAndDecryptWithKey($token, $client_key, $recipient_index);
      $payload = $jwe->getPayload();
      return $payload;
    }
    catch (\Exception $e) {
      $this->logger->error('JWE decryption failed');
      return NULL;
    }
  }

  /**
   * Get a JWS Verifier.
   *
   * @param array|null $algorithms
   *   An array of signature algorithm names to support. Unsupported algorithms
   *   will be ignored. If empty, all supported algorithms will be provided.
   *
   * @return \Jose\Component\Signature\JWSVerifier|null
   *   A JWS Verifier or NULL on failure, e.g. only unsupported algorithms
   *   were requested.
   */
  public function getJwsVerifier(?array $algorithms = []) : ?JWSVerifier {
    $algorithm_manager = $this->getSignatureAlgorithmManager($algorithms);
    if (empty($algorithm_manager)) {
      $this->logger->error('Failed to get a JWS Verifier due to requested algorithms not being supported.');
      return NULL;
    }
    $jws_verifier = new JWSVerifier($algorithm_manager);
    return $jws_verifier;
  }

  /**
   * Get a JWS Loader.
   *
   * @param array|null $signature_algorithms
   *   An array of signature algorithm names to support. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $accepted_signature_algorithms
   *   An array of signature algorithms that are acceptable.
   *   No restrictions by default.
   * @param array|null $issuers
   *   An array of issuer identifiers (iss) to accept.
   *   No restrictions by default.
   * @param string|null $audience
   *   An acceptable audience (aud). No restrictions by default.
   * @param bool|null $check_iat
   *   Require the token to have been issued in the past (iat), default TRUE.
   * @param bool|null $check_exp
   *   Require the token not to have expired (exp), default TRUE.
   * @param bool|null $check_nbf
   *   Require the token's "not before" value to be in the past, default TRUE.
   *
   * @return \Jose\Component\Signature\JWSLoader|null
   *   A JWS Loader supporting the requested algorithms and requiring the
   *   requested validations. NULL is returned on failure, e.g. if only
   *   unsupported algorithms are requested.
   */
  public function getJwsLoader(?array $signature_algorithms = [], ?array $accepted_signature_algorithms = [], ?array $issuers = NULL, ?string $audience = NULL, ?bool $check_iat = TRUE, ?bool $check_exp = TRUE, ?bool $check_nbf = TRUE) : ?JWSLoader {
    $serializer_manager = $this->getJwsSerializerManager();
    $jws_verifier = $this->getJwsVerifier($signature_algorithms);
    if (empty($jws_verifier)) {
      $this->logger->error('Failed to get a JWS Loader due to failure in getting a JWS Verifier.');
      return NULL;
    }
    $header_checker_manager = $this->getHeaderCheckerManager(
      $accepted_signature_algorithms,
      $issuers,
      $audience,
      $check_iat,
      $check_exp,
      $check_nbf
    );
    $jws_loader = new JWSLoader(
      $serializer_manager,
      $jws_verifier,
      $header_checker_manager
    );
    return $jws_loader;
  }

  /**
   * Load and verify a JWS.
   *
   * @param string $token
   *   A serialized JWS Token.
   * @param \Jose\Component\Core\JWK $provider_key
   *   The key to verify the signature against.
   * @param array|null $signature_algorithms
   *   An array of signature algorithm names to support. Unsupported
   *   ones are ignored. If omitted, all supported algorithms will be
   *   included in the loader.
   * @param array|null $accepted_signature_algorithms
   *   An array of signature algorithms that are acceptable.
   *   No restrictions by default.
   * @param array|null $issuers
   *   An array of issuer identifiers (iss) to accept.
   *   No restrictions by default.
   * @param string|null $audience
   *   An acceptable audience (aud). No restrictions by default.
   * @param bool|null $check_iat
   *   Require the token to have been issued in the past (iat), default TRUE.
   * @param bool|null $check_exp
   *   Require the token not to have expired (exp), default TRUE.
   * @param bool|null $check_nbf
   *   Require the token's "not before" value to be in the past, default TRUE.
   *
   * @return string|null
   *   JSON string containing the payload or NULL if the signature is invalid or
   *   could not be verified.
   */
  public function loadAndVerifyJws(string $token, JWK $provider_key, ?array $signature_algorithms = [], ?array $accepted_signature_algorithms = [], ?array $issuers = NULL, ?string $audience = NULL, ?bool $check_iat = TRUE, ?bool $check_exp = TRUE, ?bool $check_nbf = TRUE) : ?string {
    $jws_loader = $this->getJwsLoader(
      $signature_algorithms,
      $accepted_signature_algorithms,
      $issuers,
      $audience,
      $check_iat,
      $check_exp,
      $check_nbf
    );
    if (empty($jws_loader)) {
      $this->logger->error('Failed to load a JWS due to failure in getting a JWSLoader');
      return NULL;
    }
    try {
      $signature_index = 0;
      // This will throw on failure.
      /** @var \Jose\Component\Signature\JWS $jws */
      $jws = $jws_loader->loadAndVerifyWithKey($token, $provider_key, $signature_index);
      $payload = $jws->getPayload();
      return $payload;
    }
    catch (\Exception $e) {
      $this->logger->error('JWS loading and verification failed');
      return NULL;
    }
  }

}
