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

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

public class HttpClient {

    /**
     * Create a Get Http Request using given parameters.
     *
     * @param builder  URI builder with endpoint URL.
     * @param username Username of the user.
     * @param password Password of the user.
     * @return HttpGetRequest
     * @throws URISyntaxException
     */
    static HttpGet createGetHttpRequest(URIBuilder builder, String username, String password)
            throws URISyntaxException {

        HttpGet request = new HttpGet(builder.build());
        String auth = username + ":" + password;
        byte[] encodedAuth = Base64.encodeBase64(
                auth.getBytes(StandardCharsets.ISO_8859_1));
        String authHeader = "Basic " + new String(encodedAuth);
        // Set authorization headers.
        request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

        return request;
    }

    static HttpPatch createPatchHttpRequest(URIBuilder builder, String username, String password)
            throws URISyntaxException, UnsupportedEncodingException {


        HttpPatch request = new HttpPatch(builder.build());
        request.setHeader("Content-Type", "application/json");

        String auth = username + ":" + password;
        byte[] encodedAuth = Base64.encodeBase64(
                auth.getBytes(StandardCharsets.ISO_8859_1));
        String authHeader = "Basic " + new String(encodedAuth);
        // Set authorization headers.
        request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

        String content = "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"," +
                "\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"],\"Operations\": [{\"op\": \"add\"," +
                "\"value\": {\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\": {\"forcePasswordReset\":" +
                "true}}}]}";
        StringEntity entity = new StringEntity(content);
        request.setEntity(entity);

        return request;
    }
}
