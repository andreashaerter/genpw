<?php

/**
 * File to provide HTTP digest authentication for the static "genpw" script
 *
 *
 * PHP version 5
 *
 * LICENSE: This file is open source software (OSS) and may be copied under
 *          certain conditions. See COPYING file for details or try to contact
 *          the author(s) of this file in doubt.
 *
 * @version 2011-04-06
 * @license New/3-clause BSD (http://opensource.org/licenses/bsd-license.php)
 * @author Andreas Haerter <development@andreas-haerter.com>
 * @link http://andreas-haerter.com/projects/genpw
 * @link http://de.wikipedia.org/wiki/HTTP-Authentifizierung
 * @link http://www.php.net/manual/en/features.http-auth.php
 */



/********************************* CONFIGURE **********************************/

//define credentials (username => password). More than one user is no problem,
//simply add as much users as needed.
$cfg["http-auth"] = array("user1" => "pwd1",
                          "user2" => "pwd2");

//absolute or relative path of the genpw-file to show after an successful auth
//ATTENTION: make sure your generator is not accessible, e.g. look down with
//           a "Deny from all" .htaccess file!
$cfg["path_genpw"] = "./genpw.html";



/********************************* FUNCTIONS **********************************/

/**
 * HTTP digest authentication
 *
 * @param string The string we have to convert.
 * @return true TRUE if everything worked/auth was successful. In case of errors
 *         and/or wrong crednetials, the script will be killed (providing a
 *         message to the current client).
 * @access public
 * @author Andreas Haerter <development@andreas-haerter.com>
 * @link http://de.wikipedia.org/wiki/HTTP-Authentifizierung
 * @link http://www.php.net/manual/en/features.http-auth.php
 */
function http_digest_authentication()
{
	global $cfg;

	//get needed data (assoc array: "username" => "password")
	if (empty($cfg["http-auth"])
	    || !is_array($cfg["http-auth"])) {
		siteMessage("Config error: http-auth");
		die(); //siteMessage() should kill the script.. but better safe than sorry
	}
	$users = $cfg["http-auth"];

	//check if auth is enabled
	$realm = "Please enter your username and password";

	//send needed digest auth headers
	if (empty($_SERVER["PHP_AUTH_DIGEST"])) {
		header("HTTP/1.1 401 Unauthorized");
		header("WWW-Authenticate: Digest realm=\"".$realm."\",qop=\"auth\",nonce=\"".uniqid(mt_rand(), true)."\",opaque=\"".md5($realm.__FILE__)."\"");
		siteMessage("Wrong username and/or password!");
		die(); //siteMessage() should kill the script.. but better safe than sorry
	}

	//parse http digest
	$mandatory = array("nonce"    => true,
	                   "nc"       => true,
	                   "cnonce"   => true,
	                   "qop"      => true,
	                   "username" => true,
	                   "uri"      => true,
	                   "response" => true);
	$data = array();
	preg_match_all('@(\w+)=(?:(?:\'([^\']+)\'|"([^"]+)")|([^\s,]+))@', $_SERVER["PHP_AUTH_DIGEST"], $matches, PREG_SET_ORDER);
	foreach ($matches as $m) {
		$data[$m[1]] = $m[2] ? $m[2] : ($m[3] ? $m[3] : $m[4]);
		unset($mandatory[$m[1]]); //mandatory part was found, kick it out of the "to do" list
	}

	//create valid digest to validate the credentials
	$digest = "";
	if (isset($users[$data["username"]])) {
		$realm_digest = $realm;
		//As mentioned at <http://www.php.net/manual/en/features.http-auth.php>:
		//If safe mode is enabled, the uid of the script is added to the realm part of
		//the WWW-Authenticate header (you cannot supress this!). Therefore we have to
		//do this here, too.
		if (6 > (int)PHP_VERSION //safe_mode will be removed in PHP 6.0
		    && (int)ini_get("safe_mode") !== 0) {
			$realm_digest .= "-".getmyuid();
		}
		$digest = md5(md5($data["username"].":".$realm_digest.":".$users[$data["username"]]) //A1
		              .":".$data["nonce"].":".$data["nc"].":".$data["cnonce"].":".$data["qop"].":"
		              .md5($_SERVER["REQUEST_METHOD"].":".$data["uri"]));                    //A2
	}
	if (empty($digest)
	    || $data["response"] !== $digest) {
		header("HTTP/1.1 401 Unauthorized");
		header("WWW-Authenticate: Digest realm=\"".$realm."\",qop=\"auth\",nonce=\"".uniqid(mt_rand(), true)."\",opaque=\"".md5($realm.__FILE__)."\"");
		siteMessage("Wrong username and/or password!");
		die(); //siteMessage() should kill the script.. but  better safe than sorry
	}
    //if we are here, auth was successful
    return true;
}


/**
 * Converts some chars into needed entities for XHTML and/or XML usage
 *
 * This function is like a better htmlspecialchars() for UTF-8 XHTML (-> no
 * usage of non-numerical entities and no unneeded replacement of specialchars
 * which are within the UTF-8 space).
 *
 * @param string The string we have to convert.
 * @return string The UTF-8 string with the needed entities.
 * @access public
 * @author Andreas Haerter <development@andreas-haerter.com>
 */
function xmlent($str)
{
	return htmlspecialchars($str, ENT_QUOTES, "UTF-8", false);
}


/**
 * Shows a message to the current client and kills the script afterwards
 *
 *
 * <b>de: Zeigt eine Nachricht an den aktuellen Client an und beended
 * anschließend den Scriptablauf</b>
 *
 * @param string The message to show.
 * @access public
 * @author Andreas Haerter <development@andreas-haerter.com>
 */
function siteMessage($msg)
{
	$msg = xmlent($msg);
	echo <<< EOT
<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<!-- some help for parsers ignoring headers... -->
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<!-- I'm sure: nobody wants to see this stuff listed on Google... -->
	<meta name="allow-search" content="no" />
	<meta name="audience" content="noone" />
	<meta name="audience" content="no" />
	<meta name="robots" content="noindex,nofollow,noarchive" />
	<meta name="MSSmartTagsPreventParsing" content="true" />
	<meta name="description" content="" />
	<meta name="keywords" content="" />
	<meta http-equiv="content-language" content="gq" /> <!-- simulate "Equatorial Guinea"... not very common language for searching ;-) -->

	<!-- no title: we are living in times of "intelligent" browser address bars
	     and not everybody using the browser should "find" this listing while
	     typing - let the filename/domain decide the behaviour. -->
	<title></title>

	<style type="text/css">
	/* main tags */
	body,
	p,
	div {
		font-family: Verdana, Arial, Helvetica, Sans-Serif;
		color: #202020;
		font-size: 1em;
		line-height: 1.1em;
	}
	/* links */
	a:link,
	a:visited {
		font-family: Verdana, Arial, Helvetica, Sans-Serif;
		font-weight: normal;
		color: #373c76;
		text-decoration: underline;
	}
	a:hover {
		font-family: Verdana, Arial, Helvetica, Sans-Serif;
		font-weight: normal;
		color: #000;
		text-decoration: none;
	}
	/* headlines */
	h1{
		font-family: "Courier New", Courier;
		font-weight: bold;
		color: #424242;
		text-decoration: none;
		font-size: 2em;
		line-height: 2.1em;
		margin: 20px 0 15px 0;
	}
	</style>
</head>
<body>
	<div id="main" align="center">
		<h1>$msg</h1>
	</div>
</body>
</html>
EOT;
die();
}



/********************************** ACTION ************************************/

//do the auth
if (http_digest_authentication()) {
	//check if there is file...
	if (!file_exists($cfg["path_genpw"])) {
		siteMessage("Config error: path_genpw");
		die(); //siteMessage() should kill the script.. but better safe than sorry
	}
	//get its contents
	$content = trim(file_get_contents($cfg["path_genpw"]));
	//check if some hax0r is using a stupid webserver config to read other files than genpw
	if (empty($content)
		//search for typical strings out of "genpw"
	    || strpos($content, "rstr2b64") === false
	    || strpos($content, "a6092b96cfcd4ca937346e1bf5a59544fa9fa9c4d24e0cafa06ffa7fe3c32562592c6c070589ac90969c1223390ac225a295c3a6341401f7e320afbcd7b998f7") === false) {
		siteMessage("Config error: path_genpw");
		die(); //siteMessage() should kill the script.. but better safe than sorry
	}
	//show the generator
	echo $content;
	//kill the script
	die();
}

//if we are here, something went really wrong
header("HTTP/1.1 500 Internal Server Error");
siteMessage("internal error");

?>
