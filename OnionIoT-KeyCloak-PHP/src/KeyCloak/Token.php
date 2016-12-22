<?php

namespace OnionIoT\KeyCloak;

class Token {
	public $header;
	public $payload;
	public $signature;
	public $signed;

	public $_raw;
	protected $client_id;

	/**
	 * Construct a token.
	 *
	 * Based on a JSON Web Token string, construct a token object. Optionally
	 * if a `clientId` is provided, the token may be tested for roles with
	 * `hasRole()`.
	 *
	 * @constructor
	 *
	 * @param {String} $token The JSON Web Token formatted token string.
	 * @param {String} $client_id Optional clientId if this is an `access_token`.
	 */
	public function __construct ($token_str, $client_id = '') {
		$this->_raw = $token_str;
		$this->client_id = $client_id;

		if ($token_str) {
			try {
				$parts = explode('.', $token_str);

				$this->header = json_decode(KeyCloak::url_base64_decode($parts[0]), TRUE);
				$this->payload = json_decode(KeyCloak::url_base64_decode($parts[1]), TRUE);
				$this->signature = KeyCloak::url_base64_decode($parts[2]);
				$this->signed = $parts[0] . '.' . $parts[1];
			} catch (Exception $e) {
				$this->payload = array(
					'expires_at' => 0
				);
			}
		}
	}

	/**
	 * Returns the raw String of the grant, if available.
	 *
	 * If the raw string is unavailable (due to programatic construction)
	 * then `undefined` is returned.
	 */
    public function to_string () {
    	return $this->_raw;
    }

	/**
	 * Determine if this token is expired.
	 *
	 * @return {boolean} `true` if it is expired, otherwise `false`.
	 */
	public function is_expired () {
		$current_time = time();

		if ($this->payload['exp'] < $current_time || $this->payload['iat'] < $current_time - 86400) {
			return TRUE;
		} else {
			return FALSE;
		}
	}

	/**
	 * Determine if this token has an associated role.
	 *
	 * This method is only functional if the token is constructed
	 * with a `clientId` parameter.
	 *
	 * The parameter matches a role specification using the following rules:
	 *
	 * - If the name contains no colons, then the name is taken as the entire
	 *   name of a role within the current application, as specified via
	 *   `clientId`.
	 * - If the name starts with the literal `realm:`, the subsequent portion
	 *   is taken as the name of a _realm-level_ role.
	 * - Otherwise, the name is split at the colon, with the first portion being
	 *   taken as the name of an arbitrary application, and the subsequent portion
	 *   as the name of a role with that app.
	 *
	 * @param {String} $name The role name specifier.
	 *
	 * @return {boolean} `true` if this token has the specified role, otherwise `false`.
	 */
	public function has_role ($name) {
		if (!$this->client_id) {
			return FALSE;
		}

		$parts = explode(':', $name);

		if (count($parts) === 1) {
			return $this->has_application_role($this->client_id, $parts[0]);
		}

		if ($parts[0] === 'realm') {
			return $this->has_realm_role($parts[1]);
		}

		return $this->has_application_role($parts[0], $parts[1]);
	}

	/**
	 * Determine if this token has an associated specific application role.
	 *
	 * Even if `clientId` is not set, this method may be used to explicitly test
	 * roles for any given application.
	 *
	 * @param {String} $app_name The identifier of the application to test.
	 * @param {String} $role_name The name of the role within that application to test.
	 *
	 * @return {boolean} `true` if this token has the specified role, otherwise `false`.
	 */
	public function has_application_role ($app_name, $role_name) {
		$app_roles = $this->payload['resource_access'][appName];

		if (!$app_roles) {
			return FALSE;
		}

		return (array_search($role_name, $app_roles['roles']) ? TRUE : FALSE);
	}

	/**
	 * Determine if this token has an associated specific realm-level role.
	 *
	 * Even if `clientId` is not set, this method may be used to explicitly test
	 * roles for the realm.
	 *
	 * @param {String} $app_name The identifier of the application to test.
	 * @param {String} $role_name The name of the role within that application to test.
	 *
	 * @return {boolean} `true` if this token has the specified role, otherwise `false`.
	 */
	public function has_realm_role ($role_name) {
		return (array_search($role_name, $this->payload['realm_access']['roles']) ? TRUE : FALSE);
	}
}

