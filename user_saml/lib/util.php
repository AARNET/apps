<?php

namespace OCA\User_Saml;

use OCA\User_Saml\Hooks;
use OCA\User_Saml\Backend;

class Util {

	/**
	 * Registers user_saml to the backend and connects hooks
	 */
	public static function registerBackendAndHooks($appName) {
		\OCP\App::registerAdmin($appName, 'settings');
		\OC_User::useBackend(new Backend());
		\OCP\Util::connectHook('OC_User', 'post_createUser', '\OCA\User_Saml\Hooks', 'postCreateUser');
		\OCP\Util::connectHook('OC_User', 'post_login', '\OCA\User_Saml\Hooks', 'postLogin');
		\OCP\Util::connectHook('OC_User', 'logout', '\OCA\User_Saml\Hooks', 'logout');
	}

	/**
	 * Performs login supporting legacy login method
	 */	
	public static function doLogin($user, $password) {
		# Use legacy login if available
		if (class_exists('OC_User') && method_exists('OC_User', 'login') ) {
			return \OC_User::login($user, $password);
		} 
		return \OC::$server->getUserSession()->login($user, $password);
	}

	/**
	 * Initialise auth with SimpleSaml
	 */
	public static function loadAuth($appName) {
		\OCP\App::checkAppEnabled($appName);
		$config = \OC::$server->getConfig();
		$sspPath = $config->getAppValue($appName, 'saml_ssp_path', '');
		$spSource = $config->getAppValue($appName, 'saml_sp_source', '');
		$autocreate = $config->getAppValue($appName, 'saml_autocreate', false);

		if (!empty($sspPath) && !empty($spSource)) {
			include_once $sspPath."/lib/_autoload.php";
			$auth = new \SimpleSAML_Auth_Simple($spSource);
			$auth->requireAuth();
		}
	}
	
	/*
	 * Checks if requiring SAML authentication on current URL makes sense when
	 * forceLogin is set.
	 *
	 * Disables it when using the command line too
	 */
	public static function enforceAuth($appName='user_saml') {
		// Don't enforce for CLI
		if (\OC::$CLI) {
			return false;
		}

		$params = Array(
			"script"  => basename($_SERVER['SCRIPT_FILENAME']),
			"uri"     => \OCP\Util::getRequestUri(),
			"path_info" => isset($_SERVER['PATH_INFO']) ? basename($_SERVER['PATH_INFO']) : "",
		);
	
		$forceLogin = !in_array($params["script"], Array('cron.php', 'public.php', 'remote.php', 'status.php', 'v1.php'));
	
		// URI only checks
		$checks = Array(
			// Check for public shares not requiring authentication
			"index.php/s/",
			// Check for ocs-provider URL for OCM
			"ocs-provider/",
			"/ocs/",
		);

		// Run URI only checks
		foreach ($checks as $needle) {
			if (strstr($params["uri"], $needle)) {
				return FALSE;
			}
		}

		if (strstr($params["script"], "index.php")) {
			if (strstr($params["path_info"], "oc.js")) {
				return FALSE;
			}
			// Checks with both URI and Path Info
			$checks = Array(
				Array("uri"=>"index.php/apps/files_sharing/ajax/list.php?t=", "path"=>"list.php"),
				// Check for testremote and shareinfo on owncloud federation - Add to your owncloud on public link share
				Array("uri"=>"index.php/apps/files_sharing/testremote?remote=cloudstor", "path"=>"testremote"),
				Array("uri"=>"index.php/apps/files_sharing/shareinfo?t=", "path"=>"shareinfo"),
				// Check for pdf viewer sharing
				Array("uri"=>"index.php/apps/files_pdfviewer/?file=", "path"=>"files_pdfviewer"),
				// Check for public folder upload
				Array("uri"=>"index.php/apps/files/ajax/upload.php", "path"=>"upload.php"),
			);
	
			// Run checks with both URI and Path info
			foreach ($checks as $needle) {
				if (strstr($params["uri"], $needle["uri"]) && strstr($params["path_info"], $needle["path"])) {
					return FALSE;
				}
			}
		}
		$ocConfig = \OC::$server->getConfig(); 	
		return ($forceLogin && $ocConfig->getAppValue($appName, 'saml_force_saml_login', false));
	}
}
