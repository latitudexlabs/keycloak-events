package io.phasetwo.keycloak.resources;

import com.razorpay.*;
import io.phasetwo.keycloak.representation.ApiKeyRequest;
import io.phasetwo.keycloak.representation.UsageRequest;
import jakarta.json.Json;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONObject;
import org.keycloak.broker.provider.util.LegacySimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.representations.AccessToken;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.phasetwo.keycloak.events.UserAddListener.getDefaultOrgAttributes;

@JBossLog
public class OrgRestResource extends AbstractAdminResource {

    private static final String ORG_MGMT_BASEURL = "ORG_MGMT_BASEURL";

    private final String orgMgmtBaseurl;

    public OrgRestResource(KeycloakSession session) {
        super(session);
        this.orgMgmtBaseurl = System.getenv(ORG_MGMT_BASEURL);
    }

    private void checkForAccountAccess() {
        AccessToken.Access account = auth.getToken().getResourceAccess("account");

        if (account == null ||
                !account.isUserInRole("manage-account") ||
                !account.isUserInRole("view-profile")) {
            throw new ForbiddenException("insufficient permissions");
        }

        if (!realm.isOrganizationsEnabled()) {
            throw new BadRequestException("organization feature not enabled");
        }
    }

    /*
    @GET
    @Path("{userId}/organization")
    @Produces({MediaType.APPLICATION_JSON}) public Response getUserOrg(
            final @PathParam("userId") String userId
    ) {
        checkForAccountAccess();
        UserModel userModel = session.users().getUserById(realm, userId);
        if (userModel != null) {
            OrganizationProvider organizationProvider = org.keycloak.organization.utils.Organizations.getProvider(session);
            if (organizationProvider != null) {
                OrganizationModel organizationModel = org.keycloak.organization.utils.Organizations.resolveOrganization(session, userModel);
                if (organizationModel != null) {
                    Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
                    JSONObject org_plan_details = new JSONObject();

                    org_plan_details.put("org_id", organizationModel.getId());
                    org_plan_details.put("org_email", organizationModel.getName());

                    List<String> subscription_id = currentAttributes.get("subscription_id");
                    if (subscription_id != null && !subscription_id.isEmpty()) org_plan_details.put("subscription_id", subscription_id.get(0));

                    List<String> subscription_plan_name = currentAttributes.get("subscription_plan_name");
                    if (subscription_plan_name != null && !subscription_plan_name.isEmpty()) org_plan_details.put("subscription_plan_name", subscription_plan_name.get(0));

                    List<String> subscription_plan_id = currentAttributes.get("subscription_plan_id");
                    if (subscription_plan_id != null && !subscription_plan_id.isEmpty()) org_plan_details.put("subscription_plan_id", subscription_plan_id.get(0));

                    List<String> subscription_plan_billing_cycle = currentAttributes.get("subscription_plan_billing_cycle");
                    if (subscription_plan_billing_cycle != null && !subscription_plan_billing_cycle.isEmpty()) org_plan_details.put("subscription_plan_billing_cycle", subscription_plan_billing_cycle.get(0));

                    List<String> subscription_plan_call_limit = currentAttributes.get("subscription_plan_call_limit");
                    if (subscription_plan_call_limit != null && !subscription_plan_call_limit.isEmpty()) org_plan_details.put("subscription_plan_call_limit", subscription_plan_call_limit.get(0));

                    return Response.ok(org_plan_details).build();
                }
            }
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }
    */

    @GET
    @Path("{orgId}/attributes")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAttributes(
            final @PathParam("orgId") String orgId
    ) {
        permissions.users().requireQuery();
        permissions.users().requireView();

        if (!realm.isOrganizationsEnabled()) {
            throw new BadRequestException("organization feature not enabled");
        }
        OrganizationProvider organizationProvider = org.keycloak.organization.utils.Organizations.getProvider(session);
        if (organizationProvider == null) throw new BadRequestException("organization provider not enabled");
        OrganizationModel organizationModel = organizationProvider.getById(orgId);
        if (organizationModel == null) throw new NotFoundException(String.format("organization with id %s not found", orgId));
        return Response.ok(organizationModel.getAttributes()).build();
    }

    @PATCH
    @Path("{orgId}/attributes")
    @Produces({MediaType.APPLICATION_JSON})
    public Response patchAttributes(final @PathParam("orgId") String orgId,
                                   final Map<String, List<String>> attributes) {

        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        if (!realm.isOrganizationsEnabled()) {
            throw new BadRequestException("organization feature not enabled");
        }
        OrganizationProvider organizationProvider = org.keycloak.organization.utils.Organizations.getProvider(session);
        if (organizationProvider == null) throw new BadRequestException("organization provider not enabled");
        OrganizationModel organizationModel = organizationProvider.getById(orgId);
        if (organizationModel == null) throw new NotFoundException(String.format("organization with id %s not found", orgId));

        Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
        currentAttributes.putAll(attributes);
        organizationModel.setAttributes(currentAttributes);

        return Response.noContent().build();
    }

    @POST
    @Path("{orgId}/attributes/defaults")
    @Produces({MediaType.APPLICATION_JSON})
    public Response setOrgDefaultAttributes(final @PathParam("orgId") String orgId) {

        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        if (!realm.isOrganizationsEnabled()) {
            throw new BadRequestException("organization feature not enabled");
        }
        OrganizationProvider organizationProvider = org.keycloak.organization.utils.Organizations.getProvider(session);
        if (organizationProvider == null) throw new BadRequestException("organization provider not enabled");
        OrganizationModel organizationModel = organizationProvider.getById(orgId);
        if (organizationModel == null) throw new NotFoundException(String.format("organization with id %s not found", orgId));

        Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
        currentAttributes.putAll(getDefaultOrgAttributes());
        organizationModel.setAttributes(currentAttributes);

        return Response.noContent().build();
    }

    @POST
    @Path("generate-key")
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response generateApiKey(ApiKeyRequest request) {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + organizationModel.getId() + "/generate-key";
        return forwardPost(url, request);
    }

    @DELETE
    @Path("{key_label}")
    public Response deleteApiKey(@PathParam("key_label") String keyLabel) {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + organizationModel.getId() + "/" + keyLabel;
        return forwardDelete(url);
    }

    @GET
    @Path("keys")
    @Produces({MediaType.APPLICATION_JSON})
    public Response listApiKeys() {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + organizationModel.getId() + "/keys";
        return forwardGet(url);
    }

    @POST
    @Path("api-usage")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getApiUsage(UsageRequest request) {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + organizationModel.getId() + "/api-usage";
        return forwardPost(url, request);
    }

    @GET
    @Path("api-plan")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getPlanInfo() {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
        Map<String, Object> org_plan_details = new java.util.HashMap<>();

        org_plan_details.put("org_id", organizationModel.getId());
        org_plan_details.put("org_email", auth.getUser().getEmail());

        List<String> subscription_id = currentAttributes.get("subscription_id");
        if (subscription_id != null && !subscription_id.isEmpty()) org_plan_details.put("subscription_id", subscription_id.get(0));
        else org_plan_details.put("subscription_id", "");

        List<String> subscription_plan_name = currentAttributes.get("subscription_plan_name");
        if (subscription_plan_name != null && !subscription_plan_name.isEmpty()) org_plan_details.put("subscription_plan_name", subscription_plan_name.get(0));
        else org_plan_details.put("subscription_plan_name", "free-plan");

        List<String> subscription_plan_id = currentAttributes.get("subscription_plan_id");
        if (subscription_plan_id != null && !subscription_plan_id.isEmpty()) org_plan_details.put("subscription_plan_id", subscription_plan_id.get(0));
        else org_plan_details.put("subscription_plan_id", "");

        List<String> subscription_plan_billing_cycle = currentAttributes.get("subscription_plan_billing_cycle");
        if (subscription_plan_billing_cycle != null && !subscription_plan_billing_cycle.isEmpty()) org_plan_details.put("subscription_plan_billing_cycle", subscription_plan_billing_cycle.get(0));
        else org_plan_details.put("subscription_plan_billing_cycle", "monthly");

        List<String> subscription_plan_call_limit = currentAttributes.get("subscription_plan_call_limit");
        if (subscription_plan_call_limit != null && !subscription_plan_call_limit.isEmpty()) org_plan_details.put("subscription_plan_call_limit", subscription_plan_call_limit.get(0));
        else org_plan_details.put("subscription_plan_call_limit", "100");

        return Response.ok(org_plan_details).build();
    }

    @POST
    @Path("subscription")
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response createSubscription(Map<String, String> request) {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        try {

            Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
            List<String> subscription_plan_name = currentAttributes.get("subscription_plan_name");

            if (subscription_plan_name != null && !subscription_plan_name.isEmpty()) {
                String plan_name = subscription_plan_name.get(0);
                if (plan_name.equalsIgnoreCase("enterprise-plan")) {
                    throw new NotAllowedException("cannot create normal subscription for enterprise-plan");
                } else if (!plan_name.isEmpty() && !plan_name.equalsIgnoreCase("free-plan")) {
                    throw new NotAllowedException(String.format("organization already has an ongoing subscription to %s", plan_name));
                }
            }

            RazorpayClient razorpay = new RazorpayClient(System.getenv("RAZORPAY_KEY_ID"), System.getenv("RAZORPAY_KEY_SECRET"));

            JSONObject subscriptionRequest = new JSONObject();
            subscriptionRequest.put("plan_id", request.get("plan_id"));
            subscriptionRequest.put("total_count", 999);
            subscriptionRequest.put("quantity", 1);
            subscriptionRequest.put("customer_notify", 1);
            JSONObject notes = new JSONObject();
            notes.put("org_id",organizationModel.getId());
            subscriptionRequest.put("notes", notes);

            Subscription subscription = razorpay.subscriptions.create(subscriptionRequest);

            Map<String, Object> entity = new java.util.HashMap<>();
            entity.put("subscription_id", subscription.get("id"));
            return Response.ok(entity).build();
        } catch (RazorpayException e) {
            return errorResponse(Response.Status.BAD_REQUEST, "Subscription creation failed", e);
        }
    }

    @POST
    @Path("subscription/cancel")
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response cancelSubscription() {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        try {
            Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
            List<String> subscription_plan_name = currentAttributes.get("subscription_plan_name");

            if (subscription_plan_name != null && !subscription_plan_name.isEmpty()) {
                String plan_name = subscription_plan_name.get(0);
                if (plan_name.equalsIgnoreCase("enterprise-plan") || plan_name.equalsIgnoreCase("free-plan")) {
                    throw new NotAllowedException(String.format("cannot cancel subscription for %s", plan_name));
                }
            }

            List<String> subscription_id = currentAttributes.get("subscription_id");

            if (subscription_id == null || subscription_id.isEmpty()) {
                throw new BadRequestException("organization does not have any valid subscription");
            }

            String subscriptionId = subscription_id.get(0);
            if (subscriptionId.isEmpty()) {
                throw new BadRequestException("organization does not have any valid subscription");
            }

            RazorpayClient razorpay = new RazorpayClient(System.getenv("RAZORPAY_KEY_ID"), System.getenv("RAZORPAY_KEY_SECRET"));

            JSONObject params = new JSONObject();
            params.put("cancel_at_cycle_end", 0);
            Subscription subscription = razorpay.subscriptions.cancel(subscriptionId, params);

            String cancelled_status = subscription.get("status");

            if (cancelled_status != null && cancelled_status.equalsIgnoreCase("cancelled")) {
                Map<String, List<String>> default_org_attributes = getDefaultOrgAttributes();
                currentAttributes.putAll(default_org_attributes);
                organizationModel.setAttributes(currentAttributes);

                // TODO: issue refund
            }

            Map<String, String> entity = new java.util.HashMap<>();
            entity.put("status", cancelled_status);
            return Response.ok(entity).build();
        } catch (RazorpayException e) {
            return errorResponse(Response.Status.BAD_REQUEST, "Subscription cancel failed", e);
        }
    }

    @POST
    @Path("subscription/verify")
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response verifyPaymentSignature(Map<String, String> request) {
        checkForAccountAccess();

        OrganizationModel organizationModel = getOrgFromAuth();

        try {
            String signature = request.get("razorpay_signature");
            String paymentId = request.get("razorpay_payment_id");
            String subscriptionId = request.get("razorpay_subscription_id");

            JSONObject payload = new JSONObject();
            payload.put("razorpay_payment_id", paymentId);
            payload.put("razorpay_subscription_id", subscriptionId);
            payload.put("razorpay_signature", signature);

            boolean verified = Utils.verifySubscription(payload, System.getenv("RAZORPAY_KEY_SECRET"));
            Map<String, Boolean> entity = new java.util.HashMap<>();
            entity.put("verified", verified);

            if (verified) {
                RazorpayClient razorpay = new RazorpayClient(System.getenv("RAZORPAY_KEY_ID"), System.getenv("RAZORPAY_KEY_SECRET"));
                Subscription subscription = razorpay.subscriptions.fetch(subscriptionId);

                if (subscription != null) {
                    Map<String, List<String>> currentAttributes = organizationModel.getAttributes();
                    Map<String, List<String>> attr_map = new java.util.HashMap<>();

                    List<String> subscription_id = new java.util.ArrayList<>();
                    subscription_id.add(subscriptionId);
                    attr_map.put("subscription_id", subscription_id);

                    String plan_id = subscription.get("plan_id");
                    List<String> subscription_plan_id = new java.util.ArrayList<>();
                    subscription_plan_id.add(plan_id);
                    attr_map.put("subscription_plan_id", subscription_plan_id);

                    Plan plan = razorpay.plans.fetch(plan_id);

                    if (plan != null) {
                        String billing_cycle = plan.get("period");
                        List<String> subscription_plan_billing_cycle = new java.util.ArrayList<>();
                        subscription_plan_billing_cycle.add(billing_cycle);
                        attr_map.put("subscription_plan_billing_cycle", subscription_plan_billing_cycle);

                        JSONObject plan_items = plan.get("item");

                        String plan_name = plan_items.getString("name");
                        List<String> subscription_plan_name = new java.util.ArrayList<>();
                        subscription_plan_name.add(plan_name);
                        attr_map.put("subscription_plan_name", subscription_plan_name);

                        JSONObject notes = plan.get("notes");
                        String call_limit = notes.getString("plan_call_limit");
                        List<String> subscription_plan_call_limit = new java.util.ArrayList<>();
                        subscription_plan_call_limit.add(call_limit);
                        attr_map.put("subscription_plan_call_limit", subscription_plan_call_limit);
                    }

                    currentAttributes.putAll(attr_map);
                    organizationModel.setAttributes(currentAttributes);
                }
            }

            return Response.ok(entity).build();

        } catch (Exception e) {
            return errorResponse(Response.Status.BAD_REQUEST, "Verification failed", e);
        }
    }

    // --- Internal helper methods for forwarding HTTP calls with error handling ---

    private OrganizationModel getOrgFromAuth() {

        OrganizationModel organizationModel = org.keycloak.organization.utils.Organizations.resolveOrganization(session, auth.getUser());
        if (organizationModel == null) {
            throw new InternalServerErrorException("cannot resolve session organization");
        }
        return organizationModel;
    }

    private Response forwardGet(String url) {
        try (CloseableHttpClient http = HttpClients.createDefault()) {
            try (LegacySimpleHttp.Response response = LegacySimpleHttp.doGet(url, http).asResponse()) {
                return buildResponse(response);
            }
        } catch (IOException e) {
            return errorResponse(Response.Status.BAD_GATEWAY, "Failed to connect to upstream service", e);
        } catch (Exception e) {
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected server error", e);
        }
    }

    private Response forwardPost(String url, Object body) {
        try (CloseableHttpClient http = HttpClients.createDefault()) {
            try (LegacySimpleHttp.Response response = LegacySimpleHttp.doPost(url, http).json(body).asResponse()) {
                return buildResponse(response);
            }
        } catch (IOException e) {
            return errorResponse(Response.Status.BAD_GATEWAY, "Failed to connect to upstream service", e);
        } catch (Exception e) {
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected server error", e);
        }
    }

    private Response forwardDelete(String url) {
        try (CloseableHttpClient http = HttpClients.createDefault()) {
            try (LegacySimpleHttp.Response response = LegacySimpleHttp.doDelete(url, http).asResponse()) {
                return buildResponse(response);
            }
        } catch (IOException e) {
            return errorResponse(Response.Status.BAD_GATEWAY, "Failed to connect to upstream service", e);
        } catch (Exception e) {
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Unexpected server error", e);
        }
    }

    private Response buildResponse(LegacySimpleHttp.Response response) throws IOException {
        int status = response.getStatus();
        if (status >= 200 && status < 300) {
            return Response.status(status).entity(response.asJson()).build();
        } else {
            return Response.status(status)
                    .entity(Json.createObjectBuilder()
                            .add("error", "Upstream error")
                            .add("status", status)
                            .add("details", response.asJson().toString())
                            .build())
                    .build();
        }
    }

    private Response errorResponse(Response.Status status, String message, Exception e) {
        return Response.status(status)
                .entity(Json.createObjectBuilder()
                        .add("error", message)
                        .add("details", e.getMessage())
                        .build())
                .build();
    }
}
