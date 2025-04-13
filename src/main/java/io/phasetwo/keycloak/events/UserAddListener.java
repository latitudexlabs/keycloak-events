package io.phasetwo.keycloak.events;

import com.google.auto.service.AutoService;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.*;
import org.keycloak.organization.OrganizationProvider;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@JBossLog
@AutoService(EventListenerProviderFactory.class)
public class UserAddListener extends UserEventListenerProviderFactory {
    @Override
    UserChangedHandler getUserChangedHandler() {
        return new UserChangedHandler() {
            @Override
            void onUserAdded(KeycloakSession session, RealmModel realm, UserModel user) {
                try {
                    if (realm.isOrganizationsEnabled()) {
                        String userEmail = user.getEmail();
                        log.debugf("creating organization for user %s", userEmail);
                        OrganizationProvider organizationProvider = org.keycloak.organization.utils.Organizations.getProvider(session);
                        if (organizationProvider != null) {
                            log.infof("getting current organization for user %s", userEmail);
                            OrganizationModel organizationModel = org.keycloak.organization.utils.Organizations.resolveOrganization(session, user);
                            if (organizationModel != null) {
                                log.infof("user %s already has organization %s set", userEmail, organizationModel.getName());
                                organizationProvider.addMember(organizationModel, user);
                            } else {
                                log.infof("creating organization for user %s", userEmail);
                                try {
                                    OrganizationModel model = organizationProvider.create(userEmail, UUID.randomUUID().toString());
                                    if (model != null) {
                                        Map<String, List<String>> map = new java.util.HashMap<>();
                                        List<String> extra_attrs = new java.util.ArrayList<>();
                                        extra_attrs.add("");
                                        map.put("extra_info", extra_attrs);
                                        model.setAttributes(map);
                                        String domain = userEmail.substring(userEmail.indexOf("@") + 1);
                                        Set<OrganizationDomainModel> set = new java.util.HashSet<>();
                                        set.add(new OrganizationDomainModel(domain, true));
                                        model.setDomains(set);
                                        organizationProvider.addMember(model, user);
                                        log.infof("created organization %s (%s) for user %s", model.getName(), model.getId(), user.getEmail());
                                    }
                                } catch (ModelDuplicateException e) {
                                    log.infof("organization with name %s already exists", userEmail);
                                    OrganizationModel orgModel = organizationProvider.getByAlias(userEmail);
                                    if (orgModel != null) {
                                        organizationProvider.addMember(orgModel, user);
                                    }
                                }
                            }
                        } else {
                            log.infof("organization provider not enabled");
                        }
                    } else {
                        log.infof("organization feature not enabled for realm %s", realm.getName());
                    }
                } catch (Exception e) {
                    log.warn("Uncaught Sender error", e);
                }
            }

            @Override
            void onUserRemoved(KeycloakSession session, RealmModel realm, UserModel user) {
                
            }
        };
    }

    @Override
    public String getId() {
        return "ext-event-user-add-action";
    }
}
