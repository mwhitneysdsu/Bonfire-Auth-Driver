<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Bonfire
 *
 * An open source project to allow developers get a jumpstart their development of CodeIgniter applications
 *
 * @package   Bonfire
 * @author    Bonfire Dev Team
 * @copyright Copyright (c) 2011 - 2012, Bonfire Dev Team
 * @license   http://guides.cibonfire.com/license.html
 * @link      http://cibonfire.com
 * @since     Version 1.0
 * @filesource
 */

// ------------------------------------------------------------------------

/**
 * Auth Library
 *
 * Provides authentication functions for logging users in/out, restricting access
 * to controllers, and managing login attempts.
 *
 * Security and ease-of-use are the two primary goals of the Auth system in Bonfire.
 * This lib will be constantly updated to reflect the latest security practices that
 * we learn about, while maintaining the simple API.
 *
 * @package    Bonfire
 * @subpackage Modules_Users
 * @category   Libraries
 * @author     Bonfire Dev Team
 * @link       http://guides.cibonfire.com/helpers/file_helpers.html
 *
 */
class Auth
{

	/**
	 * The url to redirect to on successful login.
	 *
	 * @access public
	 *
	 * @var string
	 */
	public $login_destination = '/';

	/**
	 * Stores the logged in user after the first test to improve performance
	 *
	 * @access private
	 *
	 * @var object
	 */
	private $user;

	/**
	 * Stores the IP address of the current user for performance reasons
	 *
	 * @access private
	 *
	 * @var string
	 */
	private $ip_address;

	/**
	 * A pointer to the CodeIgniter instance.
	 *
	 * @access private
	 *
	 * @var object
	 */
	private $ci;

	//--------------------------------------------------------------------

	private $authentication;
	private $authorization;

	/**
	 * Grabs a pointer to the CI instance, gets the user's IP address,
	 * and attempts to automatically log in the user.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->ci =& get_instance();

		$this->ci->load->driver('users/Authentication/Authentication');
		$this->authentication = $this->ci->authentication;

		$this->ci->load->driver('users/Authorization/Authorization');
		$this->authorization = $this->ci->authorization;

		$this->login_destination = $this->authentication->login_destination;
	}

	/**
	 * Verifies that the user is logged in and has the appropriate access permissions.
	 *
	 * @access public
	 *
	 * @param string $permission A string with the permission to check for, ie 'Site.Signin.Allow'
	 * @param int    $role_id    The id of the role to check the permission against. If role_id is not passed into the method, then it assumes it to be the current user's role_id.
	 * @param bool   $override   Whether or not access is granted if this permission doesn't exist in the database
	 *
	 * @return bool TRUE/FALSE
	 */
	public function has_permission($permission, $role_id=NULL, $override=FALSE)
	{
		return $this->authorization->has_permission($permission, $role_id, $override);
	}


	/**
	 * Retrieves the logged identity from the current session.
	 * Built from the user's submitted login.
	 *
	 * @access public
	 *
	 * @return string The identity used to login.
	 */
	public function identity()
	{
		return $this->authentication->identity();
	}


	/**
	 * Checks the session for the required info, then verifies against the database.
	 *
	 * @access public
	 *
	 * @return bool|NULL
	 */
	public function is_logged_in()
	{
		return $this->authentication->is_logged_in();
	}

	/**
	 * Attempt to log the user in.
	 *
	 * @access public
	 *
	 * @param string $login    The user's login credentials (email/username)
	 * @param string $password The user's password
	 * @param bool   $remember Whether the user should be remembered in the system.
	 *
	 * @return bool
	 */
	public function login($login, $password, $remember=FALSE)
	{
		return $this->authentication->login($login, $password, $remember);
	}

	/**
	 * Destroys the autologin information and the current session.
	 *
	 * @access public
	 *
	 * @return void
	 */
	public function logout()
	{
		return $this->authentication->logout();
	}

	/**
	 * Get number of attempts to login occurred from given IP-address and/or login
	 *
	 * @param string $login (Optional) The login id to check for (email/username). If no login is passed in, it will only check against the IP Address of the current user.
	 *
	 * @return int An int with the number of attempts.
	 */
	function num_login_attempts($login=NULL)
	{
		return $this->authentication->num_login_attempts($login);
	}

	/**
	 * Checks to see whether a permission is in the system or not.
	 *
	 * @access public
	 *
	 * @param string $permission The name of the permission to check for. NOT case sensitive.
	 *
	 * @return bool TRUE/FALSE
	 */
	public function permission_exists($permission)
	{
		return $this->authorization->permission_exists($permission);
	}

	/**
	 * Checks that a user is logged in (and, optionally of the correct role)
	 * and, if not, send them to the login screen.
	 *
	 * If no permission is checked, will simply verify that the user is logged in.
	 * If a permission is passed in to the first parameter, will check the user's role
	 * and verify that role has the appropriate permission.
	 *
	 * @access public
	 *
	 * @param string $permission (Optional) A string representing the permission to check for.
	 * @param string $uri        (Optional) A string representing an URI to redirect, if FALSE
	 *
	 * @return bool TRUE if the user has the appropriate access permissions. Redirect to the previous page if the user doesn't have permissions. Redirect '/login' page if the user is not logged in.
	 */
	public function restrict($permission=NULL, $uri=NULL)
	{
		if ($this->is_logged_in() === FALSE)
		{
			$this->logout();
			Template::set_message($this->ci->lang->line('us_must_login'), 'error');
			redirect('login');
		}
		else
		{
			return $this->authorization->restrict($permission, $uri);
		}
	}

	/**
	 * Retrieves the role_id from the current session.
	 *
	 * @return int The user's role_id.
	 */
	public function role_id()
	{
		return $this->authorization->role_id();
	}

	/**
	 * Retrieves the role_name for the requested role.
	 *
	 * @access public
	 *
	 * @param int $role_id An int representing the role_id.
	 *
	 * @return string A string with the name of the matched role.
	 */
	public function role_name_by_id($role_id)
	{
		return $this->authorization->role_name_by_id($role_id);
	}

	public function user()
	{
		if (isset($this->user))
		{
			return $this->user;
		}

		$this->user = $this->authentication->user();

		return $this->user;
	}

	/**
	 * Retrieves the user_id from the current session.
	 *
	 * @access public
	 *
	 * @return int
	 */
	public function user_id()
	{
		return $this->authentication->user_id();
	}

} // end Auth

/**
 * Helper Functions
 */

if ( ! function_exists('has_permission'))
{
	/**
	 * A convenient shorthand for checking user permissions.
	 *
	 * @access public
	 *
	 * @param string $permission The permission to check for, ie 'Site.Signin.Allow'
	 * @param bool   $override   Whether or not access is granted if this permission doesn't exist in the database
	 *
	 * @return bool TRUE/FALSE
	 */
	function has_permission($permission, $override = FALSE)
	{
		$ci =& get_instance();

		return $ci->auth->has_permission($permission, NULL, $override);

	}//end has_permission()
}

if ( ! function_exists('permission_exists'))
{
	/**
	 * Checks to see whether a permission is in the system or not.
	 *
	 * @access public
	 *
	 * @param string $permission The name of the permission to check for. NOT case sensitive.
	 *
	 * @return bool TRUE/FALSE
	 */
	function permission_exists($permission)
	{
		$ci =& get_instance();

		return $ci->auth->permission_exists($permission);

	}//end permission_exists()
}

if ( ! function_exists('abbrev_name'))
{
	/**
	 * Retrieves first and last name from given string.
	 *
	 * @access public
	 *
	 * @param string $name Full name
	 *
	 * @return string The First and Last name from given parameter.
	 */
	function abbrev_name($name)
	{
		if (is_string($name))
		{
			list( $fname, $lname ) = explode( ' ', $name, 2 );
			if (is_null($lname)) // Meaning only one name was entered...
			{
				$lastname = ' ';
			}
			else
			{
				$lname = explode( ' ', $lname );
				$size = sizeof($lname);
				$lastname = $lname[$size-1]; //
			}

			return trim($fname . ' ' . $lastname) ;

		}

		/*
			TODO: Consider an optional parameter for picking custom var session.
				Making it auth private, and using auth custom var
		*/

		return $name;

	}//end abbrev_name()
}