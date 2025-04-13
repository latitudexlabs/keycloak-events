package io.phasetwo.keycloak.resources;

import io.phasetwo.keycloak.representation.ApiKeyRequest;
import io.phasetwo.keycloak.representation.UsageRequest;
import jakarta.json.Json;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.broker.provider.util.LegacySimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.organization.OrganizationProvider;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@JBossLog
public class OrgRestResource extends AbstractAdminResource {

    private static final String ORG_MGMT_BASEURL = "ORG_MGMT_BASEURL";

    private final String orgMgmtBaseurl;

    public OrgRestResource(KeycloakSession session) {
        super(session);
        this.orgMgmtBaseurl = System.getenv(ORG_MGMT_BASEURL);
    }

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
        return Response.ok(organizationModel).build();
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
    @Path("{org_id}/generate-key")
    @Produces({MediaType.APPLICATION_JSON})
    @Consumes({MediaType.APPLICATION_JSON})
    public Response generateApiKey(@PathParam("org_id") String orgId,
                                   ApiKeyRequest request) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + orgId + "/generate-key";
        return forwardPost(url, request);
    }

    @DELETE
    @Path("{org_id}/{key_label}")
    public Response deleteApiKey(@PathParam("org_id") String orgId,
                                 @PathParam("key_label") String keyLabel) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + orgId + "/" + keyLabel;
        return forwardDelete(url);
    }

    @GET
    @Path("{org_id}/keys")
    @Produces({MediaType.APPLICATION_JSON})
    public Response listApiKeys(@PathParam("org_id") String orgId) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + orgId + "/keys";
        return forwardGet(url);
    }

    @GET
    @Path("{org_id}/plan")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getPlanInfo(@PathParam("org_id") String orgId) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + orgId + "/plan";
        return forwardGet(url);
    }

    @POST
    @Path("{org_id}/api-usage")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getApiUsage(@PathParam("org_id") String orgId,
                                UsageRequest request) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();

        String url = this.orgMgmtBaseurl + "/api/v1/org/" + orgId + "/api-usage";
        return forwardPost(url, request);
    }

    // --- Internal helper methods for forwarding HTTP calls with error handling ---

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
