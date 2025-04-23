package io.phasetwo.keycloak.representation;

import lombok.Data;

import java.util.Date;

@Data
public class InvoiceSummary {
    private String id;
    private String customerId;
    private String subscriptionId;
    private String paymentId;
    private String status;
    private double amount;
    private Date createdAt;
    private String currencySymbol;
}
