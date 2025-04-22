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
                                    String alias = UUID.randomUUID().toString();
                                    OrganizationModel model = organizationProvider.create(userEmail, alias);
                                    if (model != null) {

                                        Map<String, List<String>> attr_map = getDefaultOrgAttributes();

                                        model.setAttributes(attr_map);
                                        Set<OrganizationDomainModel> set = new java.util.HashSet<>();
                                        set.add(new OrganizationDomainModel(alias, true));
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

    public static Map<String, List<String>> getDefaultOrgAttributes() {
        Map<String, List<String>> attr_map = new java.util.HashMap<>();

        List<String> subscription_plan_name = new java.util.ArrayList<>();
        subscription_plan_name.add("free-plan");
        attr_map.put("subscription_plan_name", subscription_plan_name);

        List<String> subscription_plan_id = new java.util.ArrayList<>();
        subscription_plan_id.add("");
        attr_map.put("subscription_plan_id", subscription_plan_id);

        List<String> subscription_plan_billing_cycle = new java.util.ArrayList<>();
        subscription_plan_billing_cycle.add("monthly");
        attr_map.put("subscription_plan_billing_cycle", subscription_plan_billing_cycle);

        List<String> subscription_plan_call_limit = new java.util.ArrayList<>();
        subscription_plan_call_limit.add("100");
        attr_map.put("subscription_plan_call_limit", subscription_plan_call_limit);

        List<String> subscription_id = new java.util.ArrayList<>();
        subscription_id.add("");
        attr_map.put("subscription_id", subscription_id);
        return attr_map;
    }

    @Override
    public String getId() {
        return "ext-event-user-add-action";
    }
}
