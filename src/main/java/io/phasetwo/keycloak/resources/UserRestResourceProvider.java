package io.phasetwo.keycloak.resources;

import org.keycloak.models.KeycloakSession;

public class UserRestResourceProvider extends BaseRealmResourceProvider {

    public UserRestResourceProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    protected Object getRealmResource() {
        UserRestResource userRestResource = new UserRestResource(session);
        userRestResource.setup();
        return userRestResource;
    }
}
