<?php

namespace OnionIoT\KeyCloak;

class Grant
{
	public $access_token;
	public $refresh_token;
	public $id_token;
	
	protected $client_id;
	protected $token_type;
	protected $expires_in;

	protected $_raw;

	/**
	 * Construct a new grant.
	 *
	 * The passed in argument may be another `Grant`, or any object with
	 * at least `access_token`, and optionally `refresh_token` and `id_token`,
	 * `token_type`, and `expires_in`.  Each token should be an instance of
	 * `Token` if present.
	 *
	 * If the passed in object contains a field named `__raw` that is also stashed
	 * away as the verbatim raw `String` data of the grant.
	 *
	 * @param {Object} grant The `Grant` to copy, or a simple `Object` with similar fields.
	 *
	 * @constructor
	 */
    public function __construct ($grant_data) {
    	if (gettype($grant_data) === 'string') {
    		$this->_raw = $grant_data;
            $grant_data = json_decode($this->_raw, TRUE);
    	} else {
    		$this->_raw = json_encode($grant_data);
    	}

    	$this->client_id = array_key_exists('client_id', $grant_data) ? $grant_data['client_id'] : '';

    	$this->access_token = array_key_exists('access_token', $grant_data) ? new Token($grant_data['access_token'], $this->client_id) : NULL;
		$this->refresh_token = array_key_exists('refresh_token', $grant_data) ? new Token($grant_data['refresh_token'], $this->client_id) : NULL;
		$this->id_token = array_key_exists('id_token', $grant_data) ? new Token($grant_data['id_token'], $this->client_id) : NULL;

		$this->token_type = array_key_exists('token_type', $grant_data) ? $grant_data['token_type'] : 'bearer';
		$this->expires_in = array_key_exists('expires_in', $grant_data) ? $grant_data['expires_in'] : 300;
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
	 * Determine if this grant is expired/out-of-date.
	 *
	 * Determination is made based upon the expiration status of the `access_token`.
	 *
	 * An expired grant *may* be possible to refresh, if a valid
	 * `refresh_token` is available.
	 *
	 * @return {boolean} `true` if expired, otherwise `false`.
	 */
    public function is_expired () {
    	if (!$this->access_token) {
			return TRUE;
		}

		return $this->access_token->is_expired();
    }
}
