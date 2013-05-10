<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/* /modules/users/libraries/Authorization/drivers/Authorization_default.php */

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
 * Default Driver for Authorization Library
 *
 * Provides authorization functions for restricting access.
 *
 * @package    Bonfire
 * @subpackage Modules_Users
 * @category   Libraries
 * @author     Bonfire Dev Team
 * @link       http://guides.cibonfire.com/helpers/file_helpers.html
 *
 */
class Authorization_default extends CI_Driver
{
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

	private $ci;

	public function __construct()
	{
		$this->ci =& get_instance();
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
		// move permission to lowercase for easier checking.
		$permission = strtolower($permission);

		// If no role is being provided, assume it's for the current
		// logged in user.
		if (empty($role_id))
		{
			$role_id = $this->role_id();
		}

		$this->load_permissions();
		$this->load_role_permissions($role_id);

		// did we pass?
		if (isset($this->permissions[$permission]))
		{
			$permission_id = $this->permissions[$permission];

			if (isset($this->role_permissions[$role_id][$permission_id]))
			{
				return TRUE;
			}
		}
		elseif ($override)
		{
			return TRUE;
		}

		return FALSE;

	}//end has_permission()

	/**
	 * Load the permission names from the database
	 *
	 * @access protected
	 *
	 * @param int $role_id An INT with the role id to grab permissions for.
	 *
	 * @return void
	 */
	protected function load_permissions()
	{
		if ( ! isset($this->permissions))
		{
			$this->ci->load->model('permissions/permission_model');
			$this->ci->load->model('roles/role_permission_model');

			$perms = $this->ci->permission_model->find_all();

			$this->permissions = array();

			foreach ($perms as $perm)
			{
				$this->permissions[strtolower($perm->name)] = $perm->permission_id;
			}
		}

	}//end load_permissions()

	/**
	 * Load the role permissions from the database
	 *
	 * @access protected
	 *
	 * @param int $role_id An INT with the role id to grab permissions for.
	 *
	 * @return void
	 */
	protected function load_role_permissions($role_id=NULL)
	{
		$role_id = is_null($role_id) ? $this->role_id() : $role_id;

		if ( ! isset($this->role_permissions[$role_id]))
		{
			$this->ci->load->model('permissions/permission_model');
			$this->ci->load->model('roles/role_permission_model');

			$role_perms = $this->ci->role_permission_model->find_for_role($role_id);

			$this->role_permissions[$role_id] = array();

			if (is_array($role_perms))
			{
				foreach($role_perms as $permission)
				{
					$this->role_permissions[$role_id][$permission->permission_id] = TRUE;
				}
			}
		}

	}//end load_role_permissions()

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
		// move permission to lowercase for easier checking.
		$permission = strtolower($permission);

		$this->load_permissions();

		return isset($this->permissions[$permission]);

	}//end permission_exists()

	/**
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
		// Check to see if the user has the proper permissions
		if ( ! empty($permission) && ! $this->has_permission($permission))
		{
			// set message telling them no permission THEN redirect
			Template::set_message( lang('us_no_permission'), 'attention');

			if ( ! $uri)
			{
				$uri = $this->ci->session->userdata('previous_page');

				// If previous page was the same (e.g. user pressed F5),
				// but permission has been removed, then redirecting
				// to it will cause an infinite loop.
				if ($uri == current_url())
				{
					$uri = site_url();
				}
			}
			Template::redirect($uri);
		}

		return TRUE;

	}//end restrict()

	/**
	 * Retrieves the role_id from the current session.
	 *
	 * @return int The user's role_id.
	 */
	public function role_id()
	{
		return (int) $this->ci->session->userdata('role_id');

	}//end role_id()

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
		if ( ! is_numeric($role_id))
		{
			return '';
		}

		$roles = array();

		// If we already stored the role names, use those...
		if (isset($this->role_names))
		{
			$roles = $this->role_names;
		}
		else
		{
			if ( ! class_exists('Role_model'))
			{
				$this->ci->load->model('roles/role_model');
			}
			$results = $this->ci->role_model->select('role_id, role_name')->find_all();

			foreach ($results as $role)
			{
				$roles[$role->role_id] = $role->role_name;
			}
		}

		// Try to return the role name
		if (isset($roles[$role_id]))
		{
			return $roles[$role_id];
		}

		return '';

	}//end role_name_by_id()
}