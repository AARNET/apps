<?php

/**
 * ownCloud - user_saml
 *
 * @author Sixto Martin <smartin@yaco.es>
 * @copyright 2012 Yaco Sistemas // CONFIA
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\User_Saml;

class Backend extends \OC_User_Backend {

	// cached settings
	protected $sspPath;
	protected $spSource;
	public $forceLogin;
	public $autocreate;
	public $updateUserData;
	public $protectedGroups;
	public $defaultGroup;
	public $usernameMapping;
	public $mailMapping;
	public $displayNameMapping;
	public $quotaMapping;
	public $defaultQuota;
	public $groupMapping;
	public $auth;
	protected $config;

	public function __construct() {
		$this->appName = "user_saml";
		$this->config = \OC::$server->getConfig();
		$this->loadConfig();
		$this->loadSimpleSaml();
	}

	/**
	 * Loads user_saml config options
	 */
	public function loadConfig() {
		$this->sspPath = $this->config->getAppValue($this->appName, 'saml_ssp_path', '');
		$this->spSource = $this->config->getAppValue($this->appName, 'saml_sp_source', '');
		$this->forceLogin = $this->config->getAppValue($this->appName, 'saml_force_saml_login', false);
		$this->autocreate = $this->config->getAppValue($this->appName, 'saml_autocreate', false);
		$this->updateUserData = $this->config->getAppValue($this->appName, 'saml_update_user_data', false);
		$this->defaultGroup = $this->config->getAppValue($this->appName, 'saml_default_group', '');
		$this->defaultQuota = $this->config->getAppValue($this->appName, 'saml_default_quota', '');
		$this->protectedGroups = explode(',', $this->trimConfig('saml_protected_groups'));
		$this->usernameMapping = explode(',', $this->trimConfig('saml_username_mapping'));
		$this->mailMapping = explode(',', $this->trimConfig('saml_email_mapping'));
		$this->displayNameMapping = explode(',', $this->trimConfig('saml_displayname_mapping'));
		$this->quotaMapping = explode(',', $this->trimConfig('saml_quota_mapping'));
		$this->groupMapping = explode(',', $this->trimConfig('saml_group_mapping'));
	}

	/**
	 * Loads the SimpleSAML auth object and logs user out if not authenticated and cookies are set
	 */
	public function loadSimpleSaml() {
		if (!empty($this->sspPath) && !empty($this->spSource)) {
			include_once $this->sspPath."/lib/_autoload.php";

			$this->auth = new \SimpleSAML_Auth_Simple($this->spSource);

			if (isset($_COOKIE["user_saml_logged_in"]) && $_COOKIE["user_saml_logged_in"] && !$this->auth->isAuthenticated()) { 
				unset($_COOKIE["user_saml_logged_in"]);
				setcookie("user_saml_logged_in", null, -1);
				\OC::$server->getUserSession()->logout();
			}
		}
	}

	/**
	 * Checks that the user is authenticated
	 * @param string $uid
	 * @param string $password
	 */
	public function checkPassword($uid, $password) {
		if(!$this->auth->isAuthenticated()) {
			return false;
		}

		$attributes = $this->auth->getAttributes();

		foreach($this->usernameMapping as $usernameMapping) {
			if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
				$uid = $this->getUserUID($attributes[$usernameMapping][0]);

				if(!\OCP\User::userExists($uid) && $this->autocreate) {
					return $this->createUser($uid);
				}
				return $uid;
			}
		}

		\OCP\Util::writeLog('user_saml','Unable to find the attribute used for username', \OCP\Util::DEBUG);
		$secure_cookie = \OC_Config::getValue("forcessl", false);
		$expires = time() + \OC_Config::getValue('remember_login_cookie_lifetime', 60*60*24*15);
		setcookie("user_saml_logged_in", "1", $expires, '', '', $secure_cookie);

		return false;
	}

	/**
	 * Creates a user with a random password
	 * @param string $uid
	 * returns string|false
	 */
	private function createUser($uid) {
		$userManager = \OC::$server->getUserManager();
		try {
			$userManager->createUser($uid, \OC_Util::generateRandomBytes(64));
			return $uid;
		} catch (\Exception $e) {
			\OCP\Util::writeLog('user_saml', 'Unable to create user: '.$uid.' Reason: '.$e->getMessage(), \OCP\Util::DEBUG);
		}
		return false;
	}

	/**
	 *  Returns the userid as it is stored in the users table (for case sensitivity issues)
	 *  @param string $uid
	 *  @return string
	 */
	private function getUserUID($uid) {
		$query = \OC_DB::prepare('SELECT `uid` FROM `*PREFIX*users` WHERE LOWER(`uid`) = LOWER(?)');
		$result = $query->execute(array($uid));
		if (\OC_DB::isError($result)) {
			\OCP\Util::writeLog('user_saml', \OC_DB::getErrorMessage(), \OCP\Util::ERROR);
			return false;
		}
		while ($row = $result->fetchRow()) {
			return $row['uid'];
		}
		return $uid;
	}

	/**
	 * Removes whitespace from config keys
	 * @param string $key
	 * @return string
	 */
	public function trimConfig($key) {
		return preg_replace('/\s+/', '', $this->config->getAppValue($this->appName, $key, ''));
	}

}
