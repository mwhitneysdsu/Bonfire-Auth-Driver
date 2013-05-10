<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/* /modules/users/libraries/Authentication/drivers/Authentication_default.php */

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
 * Default Driver for Authentication Library
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
class Authentication_default extends CI_Driver
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

	private $ci;

	public function __construct()
	{
		$this->ci =& get_instance();

		$this->ci->load->library('session');

		$this->ip_address = $this->ci->input->ip_address();

		$this->autologin();
	}

	//--------------------------------------------------------------------

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
		if (empty($login) || empty($password))
		{
			$error = $this->ci->settings_lib->item('auth.login_type') == 'both' ? lang('bf_username') .'/'. lang('bf_email') : ucfirst($this->ci->settings_lib->item('auth.login_type'));
			Template::set_message(sprintf(lang('us_fields_required'), $error), 'error');
			return FALSE;
		}

		$this->ci->load->model('users/User_model', 'user_model');

		// Grab the user from the db
		$selects = 'id, email, username, users.role_id, salt, password_hash, users.role_id, users.deleted, users.active, banned, ban_message';

		if ($this->ci->settings_lib->item('auth.do_login_redirect'))
		{
			$selects .= ', login_destination';
		}

		if ($this->ci->settings_lib->item('auth.login_type') == 'both')
		{
			$user = $this->ci->user_model->select($selects)->find_by(array('username' => $login, 'email' => $login), null, 'or');
		}
		else
		{
			$user = $this->ci->user_model->select($selects)->find_by($this->ci->settings_lib->item('auth.login_type'), $login);
		}

		// check to see if a value of FALSE came back, meaning that the username or email or password doesn't exist.
		if ($user == FALSE)
		{
			Template::set_message(lang('us_bad_email_pass'), 'error');
			return FALSE;
		}

		if (is_array($user))
		{
			$user = $user[0];
		}

		// check if the account has been activated.
		$activation_type = $this->ci->settings_lib->item('auth.user_activation_method');
		if ($user->active == 0 && $activation_type > 0) // in case we go to a unix timestamp later, this will still work.
		{
			if ($activation_type == 1)
			{
				Template::set_message(lang('us_account_not_active'), 'error');
			}
			elseif ($activation_type == 2)
			{
				Template::set_message(lang('us_admin_approval_pending'), 'error');
			}

			return FALSE;
		}

		// check if the account has been soft deleted.
		if ($user->deleted >= 1) // in case we go to a unix timestamp later, this will still work.
		{
			Template::set_message(sprintf(lang('us_account_deleted'), settings_item("site.system_email")), 'error');
			return FALSE;
		}

		// load do_hash()
		$this->ci->load->helper('security');

		// Try password
		if (do_hash($user->salt . $password) == $user->password_hash)
		{
			// check if the account has been banned.
			if ($user->banned)
			{
				$this->increase_login_attempts($login);
				Template::set_message($user->ban_message ? $user->ban_message : lang('us_banned_msg'), 'error');
				return FALSE;
			}

			$this->clear_login_attempts($login);

			// We've successfully validated the login, so setup the session
			$this->setup_session($user->id, $user->username, $user->password_hash, $user->email, $user->role_id, $remember,'', $user->username);

			// Save the login info
			$data = array(
				'last_login'			=> date('Y-m-d H:i:s', time()),
				'last_ip'				=> $this->ip_address,
			);
			$this->ci->user_model->update($user->id, $data);

			$trigger_data = array('user_id'=>$user->id, 'role_id'=>$user->role_id);
			Events::trigger('after_login', $trigger_data );

			// Save our redirect location
			$this->login_destination = isset($user->login_destination) && !empty($user->login_destination) ? $user->login_destination : '';

			return TRUE;
		}

		// Bad password
		else
		{
			Template::set_message(lang('us_bad_email_pass'), 'error');
			$this->increase_login_attempts($login);
		}

		return FALSE;

	}//end login()

	//--------------------------------------------------------------------

	/**
	 * Destroys the autologin information and the current session.
	 *
	 * @access public
	 *
	 * @return void
	 */
	public function logout()
	{
		$data = array(
			'user_id'	=> $this->user_id(),
			'role_id'	=> $this->ci->authorization->role_id()
		);

		Events::trigger('before_logout', $data);

		// Destroy the autologin information
		$this->delete_autologin();

		// Destroy the session
		$this->ci->session->sess_destroy();

	}//end logout()

	//--------------------------------------------------------------------

	/**
	 * Checks the session for the required info, then verifies against the database.
	 *
	 * @access public
	 *
	 * @return object (or a false value)
	 */
	public function user()
	{
		// If we've already checked this session,
		// return that.
		if (isset($this->user))
		{
			return $this->user;
		}

		$this->user = FALSE;

		// Is there any session data we can use?
		if ($this->ci->session->userdata('identity') && $this->ci->session->userdata('user_id'))
		{
			// Grab the user account
			$user = $this->ci->user_model->find($this->ci->session->userdata('user_id'));

			if ($user !== FALSE)
			{
				// load do_hash()
				$this->ci->load->helper('security');

				// Ensure user_token is still equivalent to the SHA1 of the user_id and password_hash
				if (do_hash($this->ci->session->userdata('user_id') . $user->password_hash) === $this->ci->session->userdata('user_token'))
				{
					$this->user = $user;
				}
			}
		}//end if

		if ($this->user !== FALSE)
		{
			$this->user->id = (int) $this->user->id;
			$this->user->role_id = (int) $this->user->role_id;
		}

		return $this->user;

	}//end user()

	//--------------------------------------------------------------------

	/**
	 * Checks the session for the required info, then verifies against the database.
	 *
	 * @access public
	 *
	 * @return bool|NULL
	 */
	public function is_logged_in()
	{
		// If we've already checked this session,
		// return that.
		if ( ! is_null($this->logged_in))
		{
			return $this->logged_in;
		}

		// Is there any session data we can use?
		if ($this->ci->session->userdata('identity') && $this->ci->session->userdata('user_id'))
		{
			// Grab the user account
			$user = $this->ci->user_model->select('id, username, email, salt, password_hash')->find($this->ci->session->userdata('user_id'));

			if ($user !== FALSE)
			{
				// load do_hash()
				$this->ci->load->helper('security');

				// Ensure user_token is still equivalent to the SHA1 of the user_id and password_hash
				if (do_hash($this->ci->session->userdata('user_id') . $user->password_hash) === $this->ci->session->userdata('user_token'))
				{
					$this->logged_in = TRUE;
					return TRUE;
				}
			}
		}//end if

		$this->logged_in = FALSE;
		return FALSE;

	}//end is_logged_in()

	//--------------------------------------------------------------------


	//--------------------------------------------------------------------
	// !UTILITY METHODS
	//--------------------------------------------------------------------

	/**
	 * Retrieves the user_id from the current session.
	 *
	 * @access public
	 *
	 * @return int
	 */
	public function user_id()
	{
		return (int) $this->ci->session->userdata('user_id');

	}//end user_id()

	//--------------------------------------------------------------------

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
		return $this->ci->session->userdata('identity');

	}//end identity()

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
		$this->ci->db->insert('login_attempts', array('ip_address' => $this->ip_address, 'login' => $login));

	}//end increase_login_attempts()

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
		$this->ci->db->where(array('ip_address' => $this->ip_address, 'login' => $login));

		// Purge obsolete login attempts
		$this->ci->db->or_where('UNIX_TIMESTAMP(time) <', time() - $expires);

		$this->ci->db->delete('login_attempts');

	}//end clear_login_attempts()

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
		$this->ci->db->select('1', FALSE);
		$this->ci->db->where('ip_address', $this->ip_address);
		if (strlen($login) > 0) $this->ci->db->or_where('login', $login);

		$query = $this->ci->db->get('login_attempts');
		return $query->num_rows();

	}//end num_login_attempts()

	//--------------------------------------------------------------------
	// !AUTO-LOGIN
	//--------------------------------------------------------------------

	/**
	 * Attempts to log the user in based on an existing 'autologin' cookie.
	 *
	 * @access protected
	 *
	 * @return void
	 */
	protected function autologin()
	{
		if ($this->ci->settings_lib->item('auth.allow_remember') == FALSE)
		{
			return;
		}

		$this->ci->load->helper('cookie');

		$cookie = get_cookie('autologin', TRUE);

		if ( ! $cookie)
		{
			return;
		}

		// We have a cookie, so split it into user_id and token
		list($user_id, $test_token) = explode('~', $cookie);

		// Try to pull a match from the database
		$this->ci->db->where( array('user_id' => $user_id, 'token' => $test_token) );
		$query = $this->ci->db->get('user_cookies');

		if ($query->num_rows() == 1)
		{
			// Save logged in status to save on db access later.
			$this->logged_in = TRUE;

			// If a session doesn't exist, we need to refresh our autologin token
			// and get the session started.
			if ( ! $this->ci->session->userdata('user_id'))
			{
				// Grab the current user info for the session
				$this->ci->load->model('users/User_model', 'user_model');
				$user = $this->ci->user_model->select('id, username, email, password_hash, users.role_id')->find($user_id);

				if ( ! $user)
				{
					return;
				}

				$this->setup_session($user->id, $user->username, $user->password_hash, $user->email, $user->role_id, TRUE, $test_token, $user->username);
			}
		}

	}//end autologin()

	//--------------------------------------------------------------------


	/**
	 * Create the auto-login entry in the database. This method uses
	 * Charles Miller's thoughts at:
	 * http://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice/
	 *
	 * @access protected
	 *
	 * @param int    $user_id    An int representing the user_id.
	 * @param string $old_token The previous token that was used to login with.
	 *
	 * @return bool Whether the autologin was created or not.
	 */
	protected function create_autologin($user_id, $old_token=NULL)
	{
		if ($this->ci->settings_lib->item('auth.allow_remember') == FALSE)
		{
			return FALSE;
		}

		// load random_string()
		$this->ci->load->helper('string');

		// Generate a random string for our token
		$token = random_string('alnum', 128);

		// If an old_token is presented, we're refreshing the autologin information
		// otherwise we're creating a new one.
		if (empty($old_token))
		{
			// Create a new token
			$data = array(
				'user_id'		=> $user_id,
				'token'			=> $token,
				'created_on'	=> date('Y-m-d H:i:s')
			);
			$this->ci->db->insert('user_cookies', $data);
		}
		else
		{
			// Refresh the token
			$this->ci->db->where('user_id', $user_id);
			$this->ci->db->where('token', $old_token);
			$this->ci->db->set('token', $token);
			$this->ci->db->set('created_on', date('Y-m-d H:i:s'));
			$this->ci->db->update('user_cookies');
		}

		if ($this->ci->db->affected_rows())
		{
			// Create the autologin cookie
			$this->ci->input->set_cookie('autologin', $user_id .'~'. $token, $this->ci->settings_lib->item('auth.remember_length'));

			return TRUE;
		}
		else
		{
			return FALSE;
		}

	}//end create_autologin()()

	//--------------------------------------------------------------------

	/**
	 * Deletes the autologin cookie for the current user.
	 *
	 * @access protected
	 *
	 * @return void
	 */
	protected function delete_autologin()
	{
		if ($this->ci->settings_lib->item('auth.allow_remember') == FALSE)
		{
			return;
		}

		// First things first.. grab the cookie so we know what row
		// in the user_cookies table to delete.
		$this->ci->load->helper('cookie');

		$cookie = get_cookie('autologin');
		if ($cookie)
		{
			list($user_id, $token) = explode('~', $cookie);

			// Now we can delete the cookie
			delete_cookie('autologin');

			// And clean up the database
			$this->ci->db->where('user_id', $user_id);
			$this->ci->db->where('token', $token);
			$this->ci->db->delete('user_cookies');
		}

		// Also perform a clean up of any autologins older than 2 months
		$this->ci->db->where('created_on', '< DATE_SUB(CURDATE(), INTERVAL 2 MONTH)');
		$this->ci->db->delete('user_cookies');

	}//end delete_autologin()

	//--------------------------------------------------------------------

	/**
	 * Creates the session information for the current user. Will also create an autologin cookie if required.
	 *
	 * @access protected
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

		// What are we using as login identity?
		//Should I use _identity_login() and move bellow code?

		// If "both", defaults to email, unless we display usernames globally
		if (($this->ci->settings_lib->item('auth.login_type') ==  'both'))
		{
			$login = $this->ci->settings_lib->item('auth.use_usernames') ? $username : $email;
		}
		else
		{
			$login = $this->ci->settings_lib->item('auth.login_type') == 'username' ? $username : $email;
		}

		// TODO: consider taking this out of setup_session()
		if ($this->ci->settings_lib->item('auth.use_usernames') == 0  && $this->ci->settings_lib->item('auth.login_type') ==  'username')
		{
			// if we've a username at identity, and don't want made user name, let's have an email nearby.
			$us_custom = $email;
		}
		else
		{
			// For backward compatibility, defaults to username
			$us_custom = $this->ci->settings_lib->item('auth.use_usernames') == 2 ? $user_name : $username;
		}

		// Save the user's session info

		// load do_hash()
		$this->ci->load->helper('security');

		$data = array(
			'user_id'		=> $user_id,
			'auth_custom'	=> $us_custom,
			'user_token'	=> do_hash($user_id . $password_hash),
			'identity'		=> $login,
			'role_id'		=> $role_id,
			'logged_in'		=> TRUE,
		);

		$this->ci->session->set_userdata($data);

		// Should we remember the user?
		if ($remember === TRUE)
		{
			return $this->create_autologin($user_id, $old_token);
		}

		return TRUE;

	}//end setup_session

	//--------------------------------------------------------------------

}//end Auth