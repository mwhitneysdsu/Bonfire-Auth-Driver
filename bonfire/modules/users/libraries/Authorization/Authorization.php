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
 * Authorization Library
 *
 * Provides authorization functions for restricting and managing user access.
 *
 * @package    Bonfire
 * @subpackage Modules_Users
 * @category   Libraries
 * @author     Bonfire Dev Team
 * @link       http://guides.cibonfire.com/helpers/file_helpers.html
 *
 */
class Authorization extends CI_Driver_Library
{
	/**
	 * The drivers that may be used
	 * @var array
	 */
	protected $valid_drivers = array(
		'authorization_default',
	);

	/**
	 * The driver to be used
	 * @var string
	 */
	protected $_adapter = 'default';

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

	/**
	 * Grabs a pointer to the CI instance, gets the user's IP address,
	 * and attempts to automatically log in the user.
	 *
	 * @return void
	 */
	public function __construct($config=array())
	{
		$this->ci =& get_instance();

		//$this->ip_address = $this->ci->input->ip_address();

		// We need the users language file for this to work
		// from other modules.
		$this->ci->lang->load('users/users');

		$this->ci->load->library('session');

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

		log_message('debug', 'Authorization class initialized.');

	}//end __construct()

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
	 * Verifies that the user has the appropriate access permissions.
	 *
	 * @access public
	 *
	 * @param string $permission A string with the permission to check for, ie 'Site.Signin.Allow'
	 * @param int    $role_id    The id of the role to check the permission against. If role_id is not passed into the method, then it assumes it to be the current user's role_id.
	 * @param bool   $override   Whether or not access is granted if this permission doesn't exist in the database
	 *
	 * @return bool TRUE/FALSE
	 */
	public function has_permission($permission, $role_id=NULL, $override = FALSE)
	{
		return $this->{$this->_adapter}->has_permission($permission, $role_id, $override);
	}

	/**
	 * Load the permission names from the database
	 *
	 * @access public
	 *
	 * @param int $role_id An INT with the role id to grab permissions for.
	 *
	 * @return void
	 */
	private function load_permissions()
	{
		$this->{$this->_adapter}->load_permissions();
	}

	/**
	 * Load the role permissions from the database
	 *
	 * @access public
	 *
	 * @param int $role_id An INT with the role id to grab permissions for.
	 *
	 * @return void
	 */
	private function load_role_permissions($role_id=NULL)
	{
		$this->{$this->_adapter}->load_role_permissions($role_id);
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
		return $this->{$this->_adapter}->permission_exists($permission);
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
		return $this->{$this->_adapter}->restrict($permission, $uri);
	}

	/**
	 * Retrieves the role_id from the current session.
	 *
	 * @return int The user's role_id.
	 */
	public function role_id()
	{
		return $this->{$this->_adapter}->role_id();

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
		return $this->{$this->_adapter}->role_name_by_id($role_id);
	}
} // end Authorization