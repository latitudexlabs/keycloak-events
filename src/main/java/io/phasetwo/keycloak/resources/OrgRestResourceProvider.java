package io.phasetwo.keycloak.resources;

import org.keycloak.models.KeycloakSession;

public class OrgRestResourceProvider extends BaseRealmResourceProvider {

    public OrgRestResourceProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    protected Object getRealmResource() {
        OrgRestResource userRestResource = new OrgRestResource(session);
        userRestResource.setup();
        return userRestResource;
    }
}
