<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Bonfire
 *
 * An open source project to allow developers get a jumpstart their development of CodeIgniter applications
 *
 * @package   Bonfire
 * @author    Bonfire Dev Team
 * @copyright Copyright (c) 2011 - 2013, Bonfire Dev Team
 * @license   http://guides.cibonfire.com/license.html
 * @link      http://cibonfire.com
 * @since     Version 1.0
 * @filesource
 */

// ------------------------------------------------------------------------

/**
 * Authentication Library
 *
 * Provides authentication functions for logging users in/out and managing login attempts.
 *
 * @package    Bonfire
 * @subpackage Modules_Users
 * @category   Libraries
 * @author     Bonfire Dev Team
 * @link       http://guides.cibonfire.com/helpers/file_helpers.html
 *
 */
class Authentication extends CI_Driver_Library
{
	/**
	 * The drivers that may be used
	 * @var array
	 */
	protected $valid_drivers = array(
		'authentication_default',
	);

	/**
	 * The driver to be used
	 * @var string
	 */
	protected $_adapter = 'default';

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
	 * Stores the logged in value after the first test to improve performance.
	 *
	 * @access private
	 *
	 * @var NULL
	 */
	private $logged_in = NULL;

	/**
	 * Stores the ip_address of the current user for performance reasons.
	 *
	 * @access private
	 *
	 * @var string
	 */
	private $ip_address;

	/**
	 * Stores the name of all existing permissions
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $permissions = NULL;

	/**
	 * Stores permissions by role so we don't have to scour the database more than once.
	 *
	 * @access private
	 *
	 * @var array
	 */
	private $role_permissions = array();

	/**
	 * A pointer to the CodeIgniter instance.
	 *
	 * @access private
	 *
	 * @var object
	 */
	private $ci;

	//--------------------------------------------------------------------

	/**
	 * Grabs a pointer to the CI instance, gets the user's IP address,
	 * and attempts to automatically log in the user.
	 *
	 * @return void
	 */
	public function __construct($config=array())
	{
		$this->ci =& get_instance();

		$this->ip_address = $this->ci->input->ip_address();

		// We need the users language file for this to work
		// from other modules.
		$this->ci->lang->load('users/users');

		// Driver setup
		$this->_module = 'users';

		$default_config = array(
			'adapter' => 'default',
		);

		if ( ! empty($config))
		{
			$current_config = array_merge($default_config, $config);
		}
		else
		{
			$current_config = $default_config;
		}

		// Once we have some config options, set it up here...
		foreach ($default_config as $key => $value)
		{
			if ($key == 'adapter')
			{
				if (in_array('fields_' . $current_config[$key], $this->valid_drivers))
				{
					$this->_adapter = $current_config[$key];
				}
			}
			else
			{
				$param = '_' . $key;
				$this->{$param} = $current_config[$key];
			}
		}
		// end driver setup

		log_message('debug', 'Authentication class initialized.');

	}//end __construct()

	//--------------------------------------------------------------------

	/**
	 * This retrieves the specific driver adapter and loads it
	 * @param	string	$child	The name of the adapter to load
	 * @return	object			The loaded adapter
	 */
	public function __get($child)
	{
		if ( ! isset($this->lib_name))
		{
			$this->lib_name = get_class($this);
		}

		$child_class = $this->lib_name . '_' . $child;
		$lib_name = ucfirst(strtolower(str_replace('CI_', '', $this->lib_name)));
		$driver_name = strtolower(str_replace('CI_', '', $child_class));

		if (in_array($driver_name, array_map('strtolower', $this->valid_drivers)))
		{
			// check to see if the driver is in a separate file
			if ( ! class_exists($child_class))
			{
				// check the application path first
				list($path, $_library) = Modules::find($child_class, $this->_module, 'libraries/' . $lib_name . '/drivers/');
				Modules::load_file($_library, $path);

				// it's a valid driver, but the file wasn't found
				if ( ! class_exists($child_class))
				{
					$msg = 'Unable to load the requested driver: '.$child_class;
					log_message('error', $msg);
					show_error($msg);
				}
			}

			$obj = new $child_class;
			$obj->decorate($this);
			$this->$child = $obj;
			return $this->$child;
		}

		// The requested driver isn't valid!
		$msg = 'Invalid driver requested: '.$child_class;
		log_message('error', $msg);
		show_error($msg);
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
		return $this->{$this->_adapter}->login($login, $password, $remember);
	}

	//--------------------------------------------------------------------

	/**
	 * Log the user out of the system
	 *
	 * @access public
	 *
	 * @return void
	 */
	public function logout()
	{
		$this->{$this->_adapter}->logout();
	}

	public function user()
	{
		// If we've already checked this session,
		// return that.
		if (isset($this->user))
		{
			return $this->user;
		}

		$this->user = $this->{$this->_adapter}->user();

		return $this->user;
	}
	//--------------------------------------------------------------------

	/**
	 * Verify whether the user is logged in
	 *
	 * @access public
	 *
	 * @return bool|NULL
	 */
	public function is_logged_in()
	{
		return $this->{$this->_adapter}->is_logged_in();
	}

	//--------------------------------------------------------------------


	//--------------------------------------------------------------------
	// !UTILITY METHODS
	//--------------------------------------------------------------------

	/**
	 * Retrieves the current user's user_id
	 *
	 * @access public
	 *
	 * @return int
	 */
	public function user_id()
	{
		return $this->{$this->_adapter}->user_id();

	}

	//--------------------------------------------------------------------

	/**
	 * Retrieves the logged identity for the current user.
	 * Built from the user's submitted login.
	 *
	 * @access public
	 *
	 * @return string The identity used to login.
	 */
	public function identity()
	{
		return $this->{$this->_adapter}->identity();

	}

	//--------------------------------------------------------------------


	//--------------------------------------------------------------------
	// !LOGIN ATTEMPTS
	//--------------------------------------------------------------------

	/**
	 * Records a login attempt into the database.
	 *
	 * @access protected
	 *
	 * @param string $login The login id used (typically email or username)
	 *
	 * @return void
	 */
	protected function increase_login_attempts($login)
	{
		$this->{$this->_adapter}->increase_login_attempts($login);
	}

	//--------------------------------------------------------------------

	/**
	 * Clears all login attempts for this user, as well as cleans out old logins.
	 *
	 * @access protected
	 *
	 * @param string $login   The login credentials (typically email)
	 * @param int    $expires The time (in seconds) that attempts older than will be deleted
	 *
	 * @return void
	 */
	protected function clear_login_attempts($login, $expires = 86400)
	{
		$this->{$this->_adapter}->clear_login_attempts();
	}

	//--------------------------------------------------------------------

	/**
	 * Get number of attempts to login occurred from given IP-address and/or login
	 *
	 * @param string $login (Optional) The login id to check for (email/username). If no login is passed in, it will only check against the IP Address of the current user.
	 *
	 * @return int An int with the number of attempts.
	 */
	function num_login_attempts($login=NULL)
	{
		return $this->{$this->_adapter}->num_login_attempts($login);
	}

	//--------------------------------------------------------------------
	// !AUTO-LOGIN
	//--------------------------------------------------------------------

	/**
	 * Attempts to log the user in based on an existing 'autologin' cookie.
	 *
	 * @access private
	 *
	 * @return void
	 */
	private function autologin()
	{
		$this->{$this->_adapter}->autologin();
	}

	//--------------------------------------------------------------------


	/**
	 * Create the auto-login entry in the database. This method uses
	 * Charles Miller's thoughts at:
	 * http://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice/
	 *
	 * @access private
	 *
	 * @param int    $user_id    An int representing the user_id.
	 * @param string $old_token The previous token that was used to login with.
	 *
	 * @return bool Whether the autologin was created or not.
	 */
	private function create_autologin($user_id, $old_token=NULL)
	{
		return $this->{$this->_adapter}->create_autologin($user_id, $old_token);
	}

	//--------------------------------------------------------------------

	/**
	 * Deletes the autologin cookie for the current user.
	 *
	 * @access private
	 *
	 * @return void
	 */
	private function delete_autologin()
	{
		$this->{$this->_adapter}->delete_autologin();
	}

	//--------------------------------------------------------------------

	/**
	 * Creates the session information for the current user. Will also create an autologin cookie if required.
	 *
	 * @access private
	 *
	 * @param int $user_id          An int with the user's id
	 * @param string $username      The user's username
	 * @param string $password_hash The user's password hash. Used to create a new, unique user_token.
	 * @param string $email         The user's email address
	 * @param int    $role_id       The user's role_id
	 * @param bool   $remember      A boolean (TRUE/FALSE). Whether to keep the user logged in.
	 * @param string $old_token     User's db token to test against
	 * @param string $user_name     User's made name for displaying options
	 *
	 * @return bool TRUE/FALSE on success/failure.
	 */
	protected function setup_session($user_id, $username, $password_hash, $email, $role_id, $remember=FALSE, $old_token=NULL,$user_name='')
	{
		return $this->{$this->_adapter}->setup_session($user_id, $username, $password_hash, $email, $role_id, $remember, $old_token, $user_name);
	}

	//--------------------------------------------------------------------

}//end Authentication