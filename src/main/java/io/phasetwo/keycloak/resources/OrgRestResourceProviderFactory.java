package io.phasetwo.keycloak.resources;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@JBossLog
@AutoService(RealmResourceProviderFactory.class)
public class OrgRestResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "org";

    @Override
    public String getId() {

        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {

        return new OrgRestResourceProvider(session);
    }

    @Override
    public void init(Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

}