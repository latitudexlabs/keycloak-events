package org.keycloak.broker.provider.util;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;

public class InsecureHttpClientBuilder {

    public static CloseableHttpClient create() {
        try {
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadTrustMaterial(null, new TrustAllStrategy()) // Trust all
                    .build();

            SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(
                    sslContext, NoopHostnameVerifier.INSTANCE);

            return HttpClients
                    .custom()
                    .setSSLSocketFactory(socketFactory)
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Failed to create insecure HTTP client", e);
        }
    }
}
