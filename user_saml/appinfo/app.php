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
*
*/ 

namespace OCA\User_Saml;

use OCA\User_Saml\Hooks;
use OCA\User_Saml\Backend;
use OCA\User_Saml\Util;

$appName = 'user_saml';

if (\OCP\App::isEnabled($appName)) {
	Util::registerBackendAndHooks($appName);

	$forceLogin = Util::enforceAuth($appName);
	$isApp = (isset($_GET['app']) && $_GET['app'] == $appName);

	if($isApp || (!\OCP\User::isLoggedIn() && $forceLogin && !isset($_GET['admin_login']))) {
		// Load SimpleSAML auth
        Util::loadAuth($appName);
		// Initiate login to trigger hooks
		if (!Util::doLogin('', '')) {
			$error = true;
			\OCP\Util::writeLog($appName,'Error trying to authenticate the user', \OCP\Util::DEBUG);
		}
		
		\OC_Util::redirectToDefaultPage(); // Part of legacy code, may become deprecated.
	}

	if (!\OCP\User::isLoggedIn()) {
		// Load js code in order to render the SAML link and to hide parts of the normal login form
		\OCP\Util::addScript($appName, 'utils');
	}
}
