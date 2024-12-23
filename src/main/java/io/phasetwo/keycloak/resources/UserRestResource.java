package io.phasetwo.keycloak.resources;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Map;

@JBossLog
public class UserRestResource extends AbstractAdminResource {

    public UserRestResource(KeycloakSession session) {
        super(session);
    }

    @GET
    @Path("{userId}")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAttributes(
            final @PathParam("userId") String userId
    ) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        UserModel userModel = session.users().getUserById(realm, userId);
        if (userModel == null) throw new NotFoundException(String.format("no user with id %s", userId));
        return Response.ok(userModel.getAttributes()).build();
    }

    @PATCH
    @Path("{userId}")
    @Produces({MediaType.APPLICATION_JSON})
    public Response pathAttributes(final @PathParam("userId") String userId,
                                   final Map<String, List<String>> attributes) {
        permissions.users().requireQuery();
        permissions.users().requireView();
        permissions.users().requireManage();
        UserModel userModel = session.users().getUserById(realm, userId);
        if (userModel == null) throw new NotFoundException(String.format("no user with id %s", userId));
        // Merge currentAttributes with incoming attributes
        attributes.forEach(userModel::setAttribute);
        return Response.noContent().build();
    }
}
