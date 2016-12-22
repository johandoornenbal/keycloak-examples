<?php

namespace OnionIoT\KeyCloak;

class KeyCloak {
	public $grant;

	protected $realm_id;
	protected $client_id;
	protected $secret;

	protected $realm_url;
	protected $realm_admin_url;

	protected $public_key;
	protected $is_public;

	/**
	 * Construct a grant manager.
	 *
	 * @param {Array|JSON String} $config config data.
	 *
	 * @constructor
	 */
	public function __construct ($config_data) {
		if (gettype($config_data) === 'string') {
			$config_data = json_decode($config_data, TRUE);
		}

		/**
		 * Realm ID
		 * @type {String}
		 */
		$this->realm_id = $config_data['realm'];

		/**
		 * Client/Application ID
		 * @type {String}
		 */
		$this->client_id = array_key_exists('resource', $config_data) ? $config_data['resource'] : $config_data['client_id'];

		/**
		 * If this is a public application or confidential.
		 * @type {String}
		 */
		$this->is_public = array_key_exists('public-client', $config_data) ? $config_data['public-client'] : FALSE;

		/**
		 * Client/Application secret
		 * @type {String}
		 */
		if (!$this->is_public) {
			$this->secret = array_key_exists('credentials', $config_data) ? $config_data['credentials']['secret'] : (array_key_exists('secret', $config_data) ? $config_data['secret'] : NULL);
		}

		/**
		 * Authentication server URL
		 * @type {String}
		 */
		$auth_server_url = $config_data['auth-server-url'] ? $config_data['auth-server-url'] : 'http://localhost';

		/**
		 * Root realm URL.
		 * @type {String}
		 */
		$this->realm_url = $auth_server_url . '/realms/' . $this->realm_id;

		/**
		 * Root realm admin URL.
		 * @type {String}
		 */
		$this->realm_admin_url = $auth_server_url . '/admin/realms/' . $this->realm_id;

		/**
		 * Formatted public-key.
		 * @type {String}
		 */
		$key_parts = str_split($config_data['realm-public-key'], 64);
		$this->public_key = "-----BEGIN PUBLIC KEY-----\n" . implode("\n", $key_parts) . "\n-----END PUBLIC KEY-----\n";
	}

	/**
	 * Use the direct grant API to obtain a grant from Keycloak.
	 *
	 * The direct grant API must be enabled for the configured realm
	 * for this method to work. This function ostensibly provides a
	 * non-interactive, programatic way to login to a Keycloak realm.
	 *
	 * This method can either accept a callback as the last parameter
	 * or return a promise.
	 *
	 * @param {String} $username The username.
	 * @param {String} $password The cleartext password.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_login ($username, $password) {

		$params = array(
			'grant_type' => 'password',
			'username' => $username,
			'password' => $password
		);

		$headers = array(
		    'Content-type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$params['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}

		$response = $this->send_request('POST', '/protocol/openid-connect/token', $headers, http_build_query($params));

        if ($response['code'] < 200 || $response['code'] > 299) {
            return FALSE;
        } else {
        	$this->grant = new Grant($response['body']);
        	return TRUE;
        }
	}

	/**
	 * Obtain a grant from a previous interactive login which results in a code.
	 *
	 * This is typically used by servers which receive the code through a
	 * redirect_uri when sending a user to Keycloak for an interactive login.
	 *
	 * An optional session ID and host may be provided if there is desire for
	 * Keycloak to be aware of this information.  They may be used by Keycloak
	 * when session invalidation is triggered from the Keycloak console itself
	 * during its postbacks to `/k_logout` on the server.
	 *
	 * This method returns or promise or may optionally take a callback function.
	 *
	 * @param {String} $code The code from a successful login redirected from Keycloak.
	 * @param {String} $session_id Optional opaque session-id.
	 * @param {String} $session_host Optional session host for targetted Keycloak console post-backs.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_code ($code, $redirect_uri = '', $session_host = NULL) {
		$params = array(
			'grant_type' => 'authorization_code',
			'code' => $code,
			'client_id' => $this->client_id
		);

		if (!empty($redirect_uri)) {
			$params['redirect_uri'] = $redirect_uri;
		}

		if ($session_host) {
			$params['application_session_host'] = $session_host;
		}
		
		$headers = array(
		    'Content-Type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$params['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}

		$response = $this->send_request('POST', '/protocol/openid-connect/token', $headers, http_build_query($params));

        // Shit has failed
        if ($response['code'] < 200 || $response['code'] > 299) {
            return NULL;
        } else {
        	$this->grant = new Grant($response['body']);
        	return TRUE;
        }
	}

	/**
	 * Restore a grant that has been saved in the session.
	 *
	 * This is typically used by server after the user has already logged on
	 * and the grant saved in the session. 
	 *
	 * This method returns or promise or may optionally take a callback function.
	 *
	 * @param {String} $code The code from a successful login redirected from Keycloak.
	 * @param {String} $session_id Optional opaque session-id.
	 * @param {String} $session_host Optional session host for targetted Keycloak console post-backs.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	public function grant_from_data ($grant_data) {
		$this->grant = new Grant($grant_data);

		$success = $this->validate_grant();

		if ($success) {
			return TRUE;
		} else {
			return $this->refresh_grant();
		}
	}

	/**
	 * Ensure that a grant is *fresh*, refreshing if required & possible.
	 *
	 * If the access_token is not expired, the grant is left untouched.
	 *
	 * If the access_token is expired, and a refresh_token is available,
	 * the grant is refreshed, in place (no new object is created),
	 * and returned.
	 *
	 * If the access_token is expired and no refresh_token is available,
	 * an error is provided.
	 *
	 * The method may either return a promise or take an optional callback.
	 *
	 * @return {Boolean} TRUE for success or FALSE for failure
	 */
	protected function refresh_grant () {
		// Ensure grant exists, grant is not expired, and we have a refresh token
		if (!$this->grant || $this->grant->is_expired() || !$this->grant->refresh_token) {
			$this->grant = NULL;
			return FALSE;
		}

		$params = array(
			'grant_type' => 'refresh_token',
			'refresh_token' => $this->grant->refresh_token->to_string()
		);

		$headers = array(
		    'Content-type: application/x-www-form-urlencoded'
		);

		if ($this->is_public) {
			$params['client_id'] = $this->client_id;
		} else {
			array_push($headers, 'Authorization: Basic ' . base64_encode($this->client_id . ':' . $this->secret));
		}
        
        $response = $this->send_request('POST', '/protocol/openid-connect/token', $headers, http_build_query($params));

        // Shit has failed
        if ($response['code'] < 200 || $response['code'] > 299) {
        	$this->grant = NULL;
            return FALSE;
        } else {
        	$this->grant = new Grant($response['body']);
        	return TRUE;
        }
	}

	/**
	 * Validate the grant and all tokens contained therein.
	 *
	 * This method filters a grant (in place), by nulling out
	 * any invalid tokens.  After this method returns, the
	 * passed in grant will only contain valid tokens.
	 *
	 */
	protected function validate_grant () {
		$this->grant->access_token = $this->validate_token($this->grant->access_token) ? $this->grant->access_token : NULL;
		$this->grant->refresh_token = $this->validate_token($this->grant->refresh_token) ? $this->grant->refresh_token : NULL;
		$this->grant->id_token = $this->validate_token($this->grant->id_token) ? $this->grant->id_token : NULL;

		if ($this->grant->access_token && $this->grant->refresh_token && $this->grant->id_token) {
			return TRUE;
		} else {
			return FALSE;
		}
	}

	/**
	 * Validate a token.
	 *
	 * This method accepts a token, and either returns the
	 * same token object, if valid, else, it returns `undefined`
	 * if any of the following errors are seen:
	 *
	 * - The token was undefined in the first place.
	 * - The token is expired.
	 * - The token is not expired, but issued before the current *not before* timestamp.
	 * - The token signature does not verify against the known realm public-key.
	 * @param {Token|String} $token The token to validate.
	 * @param {Boolean} $remote If validation should be performed against the Keycloak server.
	 *
	 * @return {boolean} FALSE if the token is invalid, or TRUE if token is valid.
	 *
	 */
	protected function validate_token ($token, $remote = FALSE) {
		if (!$token) {
			return FALSE;
		}

		// Perform a Remote validation against the KeyCloak server
		if ($remote) {
			$params = array(
				'access_token' => gettype($token) === 'string' ? $token : $token->to_string()
			);

			$path = '/tokens/validate?' . http_build_query($params);

			$response = $this->send_request('GET', $path);

	        if ($response['code'] < 200 || $response['code'] > 299) {
	            return FALSE;
	        } else {
	        	try {
	            	$data = json_decode($response['body'], TRUE);
	            } catch (Exception $e) {
	            	return FALSE;
	            }

		        if (array_key_exists('error', $data)) {
		        	return FALSE;
		        } else {
		        	return TRUE;
		        }
	        }

		// Validate token signature locally
		} else {
			if ($token->is_expired()) {
				return FALSE;
			}

			$verified = openssl_verify($token->signed, $token->signature, $this->public_key, OPENSSL_ALGO_SHA256);

	        if ($verified === 1) {
	        	return TRUE;
	        } else {
	            return FALSE;
	        }
		}
	}

	/**
	 * Get the account information associated with the token
	 *
	 * This method accepts a token, and either returns the
	 * user account information, or it returns NULL
	 * if it encourters error:
	 *
	 * @return {Array} An array that contains user account info, or NULL
	 */
	public function get_account ($remote = FALSE) {
		if ($remote) {
			$headers = array(
			    'Authorization: Bearer ' . $this->grant->access_token->to_string(),
			    'Accept: application/json'
			);

			$response = $this->send_request('GET', '/protocol/openid-connect/userinfo', $headers);

			if ($response['code'] < 200 || $response['code'] > 299) {
	            return NULL;
	        } else {
	        	try {
	            	$data = json_decode($response['body'], TRUE);
	            } catch (Exception $e) {
	            	return NULL;
	            }

	            if (array_key_exists('error', $data)) {
		        	return NULL;
		        } else {
		        	return $data;
		        }
	        }

		} else {
			if ($this->grant) {
				$user = $this->grant->access_token->payload;
	            return array(
	                'name' => $user['name'],
	                'username' => $user['preferred_username'],
	                'first_name' => $user['given_name'],
	                'last_name' => $user['family_name'],
	                'email' => $user['email']
	            );
			} else {
				return NULL;
			}
		}	
	}

	/**
	* Various URL getters
	**/
	public function login_url ($redirect_uri) {
        $uuid = bin2hex(openssl_random_pseudo_bytes(32));

        return $this->realm_url . '/protocol/openid-connect/auth?client_id=' . KeyCloak::encode_uri_component($this->client_id) . '&state=' . KeyCloak::encode_uri_component($uuid) . '&redirect_uri=' . KeyCloak::encode_uri_component($redirect_uri) . '&response_type=code';
    }

    public function logout_url ($redirect_uri) {
        return $this->realm_url . '/protocol/openid-connect/logout?redirect_uri=' . KeyCloak::encode_uri_component($redirect_uri);
    }

    public function account_url ($redirect_uri) {
        return $this->realm_url . '/account' . '?referrer=' . KeyCloak::encode_uri_component($this->client_id) . '&referrer_uri=' . KeyCloak::encode_uri_component($redirect_uri);
    }

	/**
	 * Send HTTP request via CURL
	 *
	 * @param {String} $method The HTTP request to use. (Default to GET)
	 * @param {String} $path The path that follows $this->realm_url, can include GET params
	 * @param {Array} $headers The HTTP headers to be passed into the request
	 * @param {String} $data The data to be passed into the body of the request
	 *
	 * @return {Array} An associative array with 'code' for response code and 'body' for request body
	 */
	protected function send_request ($method = 'GET', $path = '/', $headers = array(), $data = '') {
		$method = strtoupper($method);
		$url = $this->realm_url . $path;

		// Initiate HTTP request
        $request = curl_init();

        curl_setopt($request, CURLOPT_URL, $url);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, TRUE);

        if ($method === 'POST') {
        	curl_setopt($request, CURLOPT_POST, TRUE);
	        curl_setopt($request, CURLOPT_POSTFIELDS, $data);
	        array_push($headers, 'Content-Length: ' . strlen($data));
        }

        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        $response = curl_exec($request);
        $response_code = curl_getinfo($request, CURLINFO_HTTP_CODE);
        curl_close($request);

        return array(
        	'code' => $response_code,
        	'body' => $response
        );
	}

	/**
	 * PHP version of Javascript's encodeURIComponent that doesn't covert every character
	 *
	 * @param {String} $str The string to be encoded.
	 */
	public static function encode_uri_component ($str) {
        $revert = array(
            '%21' => '!', 
            '%2A' => '*', 
            '%27' => "'", 
            '%28' => '(', 
            '%29' => ')'
        );
        return strtr(rawurlencode($str), $revert);
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function url_base64_decode ($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function url_base64_encode ($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}