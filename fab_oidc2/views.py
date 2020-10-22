import os
from flask import redirect, request, render_template_string
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from flask_admin import expose
from urllib.parse import quote
from logging import getLogger
log = getLogger(__name__)

# Set the OIDC field that should be used as a username
USERNAME_OIDC_FIELD = os.getenv('USERNAME_OIDC_FIELD', default='sub')
FIRST_NAME_OIDC_FIELD = os.getenv('FIRST_NAME_OIDC_FIELD',
                                  default='nickname')
LAST_NAME_OIDC_FIELD = os.getenv('LAST_NAME_OIDC_FIELD',
                                 default='name')
ENABLE_ROLE_OIDC_ACCESS = os.getenv('ENABLE_ROLE_OIDC_ACCESS',
                                    default='True')
ROLES_OIDC_FIELD = os.getenv('ROLES_OIDC_FIELD',
                             default='roles')


class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):

        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))

            # Get user roles.
            user_roles = oidc.user_getfield(ROLES_OIDC_FIELD)
            
            # Iterate through each role, and check if its available.
            assign_roles = []
            if ENABLE_ROLE_OIDC_ACCESS.lower() in ['true']:
                if user_roles:
                    if isinstance(user_roles, str):
                        user_roles = [user_roles]
                    for role in user_roles:
                        fetch_role = sm.find_role(role)
                        if fetch_role:
                            assign_roles.append(fetch_role)
            else:
                if sm.auth_user_registration_role:
                    user_reg_role = sm.find_role(sm.auth_user_registration_role)
                    if user_reg_role:
                        assign_roles.append(sm.find_role(sm.auth_user_registration_role))

            # Thrown 401 if no roles are assigned to the user
            if len(assign_roles) == 0:
                log.debug(f"No role available for the user {oidc.user_getfield('email')} for access...")
                return render_template_string("Unauthorized Access! Please contact administrator...")

            # Get user info.
            info = oidc.user_getinfo([
                USERNAME_OIDC_FIELD,
                FIRST_NAME_OIDC_FIELD,
                LAST_NAME_OIDC_FIELD,
                'email',
            ])

            # Add user, if not in system, else update user
            if user is None:
                user = sm.add_user(
                    username=info.get(USERNAME_OIDC_FIELD),
                    first_name=info.get(FIRST_NAME_OIDC_FIELD),
                    last_name=info.get(LAST_NAME_OIDC_FIELD),
                    email=info.get('email'),
                    role=assign_roles[0]
                )

                user.roles.clear()
                user.roles.extend(assign_roles)
                sm.update_user(user)
                log.debug(f"New User added {info.get('email')} with roles {assign_roles}")
            else:
                # Update user information
                update_user = sm.find_user(email=info.get('email'))

                update_user.username = info.get(USERNAME_OIDC_FIELD)
                update_user.first_name = info.get(FIRST_NAME_OIDC_FIELD)
                update_user.last_name = info.get(LAST_NAME_OIDC_FIELD)
                update_user.email = info.get('email')
                update_user.active = True

                update_user.roles.clear()
                update_user.roles.extend(assign_roles)

                sm.update_user(update_user)
                log.debug(f"Logged in User {info.get('email')} with roles {assign_roles}")

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):

        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip(
            '/') + self.appbuilder.get_url_for_login

        logout_uri = oidc.client_secrets.get(
            'issuer') + '/protocol/openid-connect/logout?redirect_uri='
        if 'OIDC_LOGOUT_URI' in self.appbuilder.app.config:
            logout_uri = self.appbuilder.app.config['OIDC_LOGOUT_URI']

        return redirect(logout_uri + quote(redirect_url))
