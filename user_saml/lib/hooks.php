<?php
/**
 * ownCloud - user_saml
 *
 * @author Sixto Martin <smartin@yaco.es>
 *
 * @copyright 2017 Yaco Sistemas // CONFIA
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

/**
 * This class contains all the login hooks
 */
namespace OCA\User_Saml;

use OCA\User_Saml\Backend;

class Hooks {

	/**
	 * @param Array $parameters
	 * @return boolean
	 */ 
	public static function postLogin($parameters) {
		$uid = '';
		$userid = $parameters['uid'];
		$samlBackend = new Backend();

		if ($samlBackend->auth->isAuthenticated()) {
			$attributes = $samlBackend->auth->getAttributes();

			foreach ($samlBackend->usernameMapping as $usernameMapping) {
				if (array_key_exists($usernameMapping, $attributes) && !empty($attributes[$usernameMapping][0])) {
					$uid = $attributes[$usernameMapping][0];
					break;
				}
			}

			if (!empty($uid) && strtolower($uid) == strtolower($userid)) {
				if ($samlBackend->updateUserData) {
					$userAttributes = self::getUserAttributes($uid, $samlBackend);
					self::updateUserData($uid, $userAttributes);
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * @param Array $parameters
	 */ 
	public static function postCreateUser($parameters) {
		$uid = $parameters['uid'];
		$samlBackend = new Backend();

		if (!$samlBackend->updateUserData) {
			// Ensure that user data will be filled at least once
			$userAttributes = self::getUserAttributes($uid, $samlBackend);
			self::updateUserData($uid, $userAttributes, true);
		}
	}

	/**
	 * @param Array $parameters
	 * @return boolean
	 */ 
	public static function logout($parameters) {
		$samlBackend = new Backend();
		if ($samlBackend->auth->isAuthenticated()) {
			unset($_COOKIE["SimpleSAMLAuthToken"]);
			setcookie('SimpleSAMLAuthToken', '', time()-3600, \OC::$WEBROOT);
			setcookie('SimpleSAMLAuthToken', '', time()-3600, \OC::$WEBROOT . '/');
			$samlBackend->auth->logout();
		}
		return true;
	}


	/**
	 * @param string $uid
	 * @param $samlBackend
	 * @return Array
	 */ 
	public static function getUserAttributes($uid, $samlBackend) {
		$attributes = $samlBackend->auth->getAttributes();
		$result = Array(
			'email' => '',
			'display_name' => '',
			'groups' => Array(),
			'quota' => '',
			'protected_groups' => $samlBackend->protectedGroups,
		);
		
		// Get email attribute
		foreach ($samlBackend->mailMapping as $mailMapping) {
			if (array_key_exists($mailMapping, $attributes) && !empty($attributes[$mailMapping][0])) {
				$result['email'] = $attributes[$mailMapping][0];
				break;
			}
		}

		// Get display name attribute
		foreach ($samlBackend->displayNameMapping as $displayNameMapping) {
			if (array_key_exists($displayNameMapping, $attributes) && !empty($attributes[$displayNameMapping][0])) {
				$result['display_name'] = $attributes[$displayNameMapping][0];
				break;
			}
		}

		// Get groups
		foreach ($samlBackend->groupMapping as $groupMapping) {
			if (array_key_exists($groupMapping, $attributes) && !empty($attributes[$groupMapping])) {
				$result['groups'] = array_merge($result['groups'], $attributes[$groupMapping]);
			}
		}
		if (empty($result['groups']) && !empty($samlBackend->defaultGroup)) {
			$result['groups'] = array($samlBackend->defaultGroup);
		}

		// Get quota
		if (!empty($samlBackend->quotaMapping)) {
			foreach ($samlBackend->quotaMapping as $quotaMapping) {
				if (array_key_exists($quotaMapping, $attributes) && !empty($attributes[$quotaMapping][0])) {
					$result['quota'] = $attributes[$quotaMapping][0];
					break;
				}
			}
		}
		if (empty($result['quota']) && !empty($samlBackend->defaultQuota)) {
			$result['quota'] = $samlBackend->defaultQuota;
		}
		return $result;	
	}

	/**
	 * @param string $uid
	 * @param Array $attributes
	 * @param boolean $just_created
	 */
	public static function updateUserData($uid, $attributes=array(), $just_created=false) {
		\OC_Util::setupFS($uid);
		if ($just_created) {
			self::updateCreatedAt($uid);
		}
		if(isset($attributes['email'])) {
			self::updateMail($uid, $attributes['email']);
		}
		if (isset($attributes['groups'])) {
			self::updateGroups($uid, $attributes['groups'], $attributes['protected_groups'], $just_created);
		}
		if (isset($attributes['display_name'])) {
			self::updateDisplayName($uid, $attributes['display_name']);
		}
		if (isset($attributes['quota'])) {
			self::updateQuota($uid, $attributes['quota']);
		}
	}	

	/**
	 * @param string $uid
	 * @param string $email
	 */
	public static function updateMail($uid, $email) {
		$config = \OC::$server->getConfig();
		if ($email != $config->getUserValue($uid, 'settings', 'email', '')) {
			$config->setUserValue($uid, 'settings', 'email', $email);
		}
	}

	/**
	 * @param string $uid
	 */
	public static function updateCreatedAt($uid) {
		$config = \OC::$server->getConfig();
		$timestamp = time();
		if (!$config->getUserValue($uid, 'settings', 'createdAt', false)) {
			$config->setUserValue($uid, 'settings', 'createdAt', $timestamp);
		}
	}

	/**
	 * @param string $uid
	 * @param Array $groups
	 * @param Array $protectedGroups
	 * @param boolean $just_created
	 */
	public static function updateGroups($uid, $groups, $protectedGroups=array(), $just_created=false) {
		/*
		// Commented out as this will auto update groups the user is in and we don't want that.
		$groupManager = \OC::$server->getGroupManager();
		if(!$just_created) {
			$old_groups = $groupManager->getUserGroups($uid);
			foreach($old_groups as $group) {
				if(!in_array($group, $protectedGroups) && !in_array($group, $groups)) {
					$group = $groupManager->get($group);
					$group->removeUser($uid);
				}
			}
		}

		foreach($groups as $group) {
			if ($groupManager->groupExists($group)) {
				$group = $groupManager->get($group);
			} else {
				$group = $groupManager->createGroup($group);
			}
			if (isset($group) && !$group->inGroup($uid)) {
				$group->addUser($uid);
			}
		}
		*/
	}

	/**
	 * @param string $uid
	 * @param string $displayName
	 */
	public static function updateDisplayName($uid, $displayName) {
		if ($currentUser = \OC::$server->getUserManager()->get($uid)) {
			$currentUser->setDisplayName($displayName);
		}
	}

	/**
	 * @param string $uid
	 * @param string $quota
	 */
	public static function updateQuota($uid, $quota) {
		if (!empty($quota)) {
			$config = \OC::$server->getConfig();
			$config->setUserValue($uid, 'files', 'quota', \OCP\Util::computerFileSize($quota));
		}
	}
}
