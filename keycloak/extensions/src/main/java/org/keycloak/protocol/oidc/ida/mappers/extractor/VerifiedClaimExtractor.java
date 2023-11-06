package org.keycloak.protocol.oidc.ida.mappers.extractor;

import org.jboss.logging.Logger;

import com.arakelian.jq.ImmutableJqLibrary;
import com.arakelian.jq.ImmutableJqRequest;
import com.arakelian.jq.JqRequest;
import com.arakelian.jq.JqResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.JQ_DATE_FUNCTIONS;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_ESSENTIAL;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_LIST;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_MAX_AGE;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_PURPOSE;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_VALUE;
import static org.keycloak.protocol.oidc.ida.mappers.extractor.ExtractorConstants.KEY_FILTER_VALUES;

/**
 * Class that implements the process of retrieving a request claim from a user's Verified Claims
 */
public class VerifiedClaimExtractor {
    private static final Logger LOG = Logger.getLogger(VerifiedClaimExtractor.class);

    /**
     * This method acts like a parser from a "verified_claims" request to a string of a JQ filter. It will build a 
     * filter for each JSON object of the request and combine them all in a single string. <br/><br/>
     * 
     * Each filter consists of a "filter" and a "JSON" part.
     * 
     * @param json
     * @return
     */
    private static String buildJqFilter(JsonNode json) {
        StringBuilder jqJson = new StringBuilder();
        StringBuilder jqFilter = new StringBuilder("."); 

        buildJqFilterHelper(json, jqJson, jqFilter, "");

        return String.format("(%s|%s) // null", jqFilter.toString(), jqJson.toString());
    }

    /**
     * Helper to build the JQ filter.
     * 
     * @param json - a JsonNode object to be filtered
     * @param jqJson - the JSON part of the JQ string
     * @param jqFilter - the filter part of the JQ string
     * @param curPath - string representing the current relative path of the object being parsed
     */
    private static void buildJqFilterHelper(JsonNode json, StringBuilder jqJson, StringBuilder jqFilter, String curPath) {
        jqJson.append("{");

        json.fields().forEachRemaining(entry -> {
            String fieldName = entry.getKey();
            JsonNode fieldValue = entry.getValue();
            String path = curPath + String.format(".%s", fieldName);

            if (fieldValue.isNull()) {
            // If the requested field is null, try to fill it

                jqJson.append(fieldName).append(":" + path);
            } else if (fieldValue.isObject()) {
            // If the requested field is an object, some checks will be made

                if (KEY_FILTER_LIST.stream().anyMatch(key -> fieldValue.has(key))) {
                // If the requested field has a filter specified
                    
                    jqJson.append(fieldName).append(":" + path);

                    if (fieldValue.has(KEY_FILTER_VALUE)) {
                    // If a single value was specified, use it to filter parent node

                        jqFilter.append(String.format("|select(%s==%s)", path, fieldValue.get(KEY_FILTER_VALUE).toString()));
                    }

                    if (fieldValue.has(KEY_FILTER_VALUES)) {
                    // If more than one value was specified, use them to filter parent node, joined by "or" condition

                        List<String> conditions = new ArrayList<String>();

                        fieldValue.get(KEY_FILTER_VALUES).elements().forEachRemaining(valueNode -> {
                            conditions.add(String.format("%s==%s", path, valueNode.toString()));
                        });

                        jqFilter.append(String.format("|select(%s)", String.join(" or ", conditions)));
                    }
                    
                    if (fieldValue.has(KEY_FILTER_ESSENTIAL)) {
                    // If the requested field is essential, it will be used to filter it's parent as well

                        jqFilter.append(String.format("|select(%s!=null)", path));
                    }

                    if (fieldValue.has(KEY_FILTER_MAX_AGE)) {
                    // If the requested field has a max_age specified

                        jqFilter.append(String.format("|select(isRecentEnough([%s, %s]))", path, fieldValue.get(KEY_FILTER_MAX_AGE)));
                    }

                    if (fieldValue.has(KEY_FILTER_PURPOSE)) {
                    // If the requested field has a purpose specified

                        // TODO
                    }
                } else {
                // If the requested field is simply an object, recursively try to filter it

                    if (fieldName != null) jqJson.append(fieldName).append(":");

                    jqJson.append(String.format("(%s|%s)", path, buildJqFilter(fieldValue)));
                }
            } else if (fieldValue.isArray()) {
            // If the requested field is an array

                StringBuilder arrayFilter = new StringBuilder();
                fieldValue.elements().forEachRemaining(jsonNode -> { arrayFilter.append(buildJqFilter(jsonNode)); });

                jqJson.append(fieldName).append(String.format(":[%s[]|%s]", path, arrayFilter.toString()));
            }

            jqJson.append(",");
        });

        // Removes unwanted comma
        if (jqJson.charAt(jqJson.length() - 1) == ',') jqJson.deleteCharAt(jqJson.length() - 1); 

        jqJson.append("}");
    }

    /**
     * Removes all null or empty elements from a JsonNode, recursively
     * 
     * @param node
     * @return 'true' if any element was removed, 'false' otherwise
     */
    private static boolean stripNulls(JsonNode node) {
        boolean nodeRemoved = false;
        Iterator<JsonNode> it = node.iterator();

        while (it.hasNext()) {
            JsonNode child = it.next();
            if (child.isNull() || (child.isArray() && child.size() == 0)) {
                it.remove();
                nodeRemoved = true;
            } else {
                nodeRemoved |= stripNulls(child);
            }
        }

        return nodeRemoved;
    }

    public static JsonNode getVerifiedClaims(JsonNode requestedVerifiedClaims, JsonNode userVerifiedClaims) {
        // Builds the JQ filter used to select user's verified claims
        String jqFilter = JQ_DATE_FUNCTIONS + buildJqFilter(requestedVerifiedClaims);

        // Executes a JQ request on user's verified claims
        JqRequest jqRequest = ImmutableJqRequest.builder()
                .lib(ImmutableJqLibrary.of())
                .input(userVerifiedClaims.toString())
                .filter(jqFilter)
                .build();
        JqResponse jqResponse = jqRequest.execute();

        if (jqResponse.hasErrors()) {
        // This shouldn't happen

            return null;
        }
        
        try {
            JsonNode verifiedClaims = new ObjectMapper().readTree(jqResponse.getOutput());
            while (stripNulls(verifiedClaims));
            
            LOG.info(verifiedClaims.toPrettyString());
        } catch (Exception e) {
            // NOOP
        }

        return null;
    }
}