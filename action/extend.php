<?php

/**
 * Class action_plugin_usermanagerextended_extend
 */
class action_plugin_usermanagerextended_extend extends DokuWiki_Action_Plugin
{

    /**
     * @param \Doku_Event_Handler $controller
     */
    public function register(\Doku_Event_Handler $controller)
    {
        $controller->register_hook('ADMINPLUGIN_ACCESS_CHECK', 'AFTER', $this, 'handleAccess');
        $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'handlePermissions');
    }

    /**
     * Grant managers access to user manager
     *
     * @param \Doku_Event $event
     */
    public function handleAccess(\Doku_Event $event)
    {
        if ($event->data['instance'] instanceof \admin_plugin_usermanager) {
            $event->data['hasAccess'] = auth_ismanager();
        }
    }

    /**
     * Prevent managers from making changes beyond their privileges:
     * - do not modify superusers
     * - do not create superusers or managers (by adding users or groups)
     *
     * @param \Doku_Event $event
     * @return bool
     */
    public function handlePermissions(\Doku_Event $event)
    {
        // preliminary checks
        if (auth_isadmin()) return true;
        if (!auth_ismanager()) return $this->deny($event);

        $modUser = $event->data['params'][0];

        // more checks
        if (is_array($modUser)) {
            foreach ($modUser as $user) {
                $this->checkModUser($user, $event);
            }
        } else {
            $this->checkModUser($modUser, $event);
        }

        return true;
    }

    /**
     * Check if modification of given user is allowed
     *
     * @param string $modUser
     * @param \Doku_Event $event
     * @return bool
     */
    protected function checkModUser($modUser, \Doku_Event $event)
    {
        global $auth, $conf;

        // rule: don't touch admins
        // auth_isadmin() needs to receive groups or it will match against the groups of REMOTE_USER!
        $existingUser = $auth->getUserData($modUser);
        if ($existingUser && auth_isadmin($modUser, $existingUser['grps'])) return $this->deny($event);

        // rule: don't create admins or managers
        // check groups in modification parameters
        if ($event->data['type'] === 'create') {
            $groups = $event->data['params'][4];
        } elseif ($event->data['type'] === 'modify') {
            $groups = $event->data['params'][1]['grps'];
        }

        // those new groups should be enough because we do not prevent demoting managers
        // like we did with admins
        if (
            !empty($groups) &&
            auth_isMember(
                join(',', [$conf['superuser'], $conf['manager']]),
                $modUser,
                $groups
            )
        ) {
            return $this->deny($event);
        }

        return true;
    }

    /**
     * Wrap up modification denial
     *
     * @param \Doku_Event $event
     * @return false
     */
    protected function deny(\Doku_Event $event)
    {
        $event->preventDefault();

        msg($this->getLang('error_forbidden'), -1);
        return false;
    }
}
