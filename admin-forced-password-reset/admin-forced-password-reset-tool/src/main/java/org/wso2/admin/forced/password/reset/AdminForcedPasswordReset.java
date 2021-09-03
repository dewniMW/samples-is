/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.admin.forced.password.reset;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

public class AdminForcedPasswordReset {

    private static final String SCIM_USER_ENDPOINT = "scim2/Users";
    private static final String PATH_SEPARATOR = "/";

    private static final Logger LOGGER = Logger.getLogger(AdminForcedPasswordReset.class.getName());

    public static void main(String args[]) throws IOException, KeyStoreException,
            NoSuchAlgorithmException, KeyManagementException, URISyntaxException {

        String hostAddress = args[0];
        String username = args[1];
        String password = args[2];

        if (hostAddress == null || username == null || password == null) {
            LOGGER.log(Level.INFO,
                    "Invalid arguments! Please provide valid arguments to host address, username and password.");
            return;
        }

        // curl -X GET "https://localhost:9443/scim2/Users?attributes=id&filter=userName+sw+USERSTORE01/" -H "accept: application/scim+json" -H "authorization: Basic YWRtaW46YWRtaW4=" -k -v

        // Create a get request to retrieve list users from SCIM 2.0
        URIBuilder uriBuilder = new URIBuilder(hostAddress + PATH_SEPARATOR + SCIM_USER_ENDPOINT +
                "?attributes=id&filter=userName+sw+ASGARDEO-USER/");
        HttpGet getHttpRequest = HttpClient.createGetHttpRequest(uriBuilder, username, password);

        final SSLContext context = new SSLContextBuilder()
                .loadTrustMaterial(null, (x509CertChain, authType) -> true).build();

        try (CloseableHttpClient closeableHttpClient = HttpClientBuilder.create().setSSLContext(context).build()) {
            HttpResponse httpResponse = closeableHttpClient.execute(getHttpRequest);

            String stringResponse;
            // Check response status code is OK
            if (HttpStatus.SC_OK == httpResponse.getStatusLine().getStatusCode()) {
                stringResponse = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
                JsonNode jsonTree = new ObjectMapper().readTree(stringResponse);
                JsonNode usersNode = jsonTree.at("/Resources");

                if (usersNode.isArray()) {
                    for (int i = 0; i < usersNode.size(); i++) {
                        String id = usersNode.get(i).get("id").textValue();

                        URIBuilder builder = new URIBuilder(hostAddress + PATH_SEPARATOR + SCIM_USER_ENDPOINT +
                                PATH_SEPARATOR + id);

                        //curl -v -k --user admin:admin --header "Content-Type:application/json" 'https://localhost:9443/scim2/Users/d0af4cec-9e4e-4cc2-96de-1f8f39de0e83' -X PATCH -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"Operations": [{"op": "add","value": {"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"forcePasswordReset":true}}}]}'

                        HttpPatch request = HttpClient.createPatchHttpRequest(builder, username, password);

                        final SSLContext sslContext = new SSLContextBuilder()
                                .loadTrustMaterial(null, (x509CertChain, authType) -> true).build();

                        try (CloseableHttpClient client = HttpClientBuilder.create()
                                .setSSLContext(sslContext).build()) {
                            HttpResponse response = client.execute(request);

                            if (HttpStatus.SC_OK == response.getStatusLine().getStatusCode()) {
                                LOGGER.log(Level.INFO, "Admin forced password reset is successful for user " +
                                        "with id: " + id);
                            } else {
                                LOGGER.log(Level.INFO, "Admin forced password reset failed for user " +
                                        "with id: " + id + ". " + request.getMethod() + " request to " +
                                        request.getURI().toString() + " returned the status code : " +
                                        response.getStatusLine());
                            }
                        }
                    }
                }
            } else {
                LOGGER.log(Level.INFO, "Retrieval of users failed. " + getHttpRequest.getMethod() +
                        " request to " + getHttpRequest.getURI().toString() + " returned the status code : " +
                        httpResponse.getStatusLine());
            }
        }
    }
}
