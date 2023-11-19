/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.representations;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Claims parameter as described in the OIDC specification https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@SuppressWarnings("rawtypes")
public class ClaimsRepresentation {
    @JsonProperty("id_token")
    private ClaimWrapper idTokenClaims;

    @JsonProperty("userinfo")
    private ClaimWrapper userinfoClaims;

    public ClaimWrapper getIdTokenClaims() {
        return idTokenClaims;
    }

    public void setIdTokenClaims(ClaimWrapper idTokenClaims) {
        this.idTokenClaims = idTokenClaims;
    }

    public ClaimWrapper getUserinfoClaims() {
        return userinfoClaims;
    }

    public void setUserinfoClaims(ClaimWrapper userinfoClaims) {
        this.userinfoClaims = userinfoClaims;
    }

    // Helper methods

    /**
     *
     * @param claimName
     * @param ctx Whether we ask for claim to be presented in idToken or userInfo
     * @return true if claim is presented in the claims parameter either as "null" claim (See OIDC specification for definition of null claim) or claim with some value
     */
    public boolean isPresent(String claimName, ClaimContext ctx) {
        if (ctx == ClaimContext.ID_TOKEN) {
            return idTokenClaims != null && idTokenClaims.containsKey(claimName);
        } else if (ctx == ClaimContext.USERINFO){
            return userinfoClaims != null && userinfoClaims.containsKey(claimName);
        } else {
            throw new IllegalArgumentException("Invalid claim context");
        }
    }

    /**
     *
     * @param claimName
     * @param ctx Whether we ask for claim to be presented in idToken or userInfo
     * @return true if claim is presented in the claims parameter as "null" claim (See OIDC specification for definition of null claim)
     */
    public boolean isPresentAsNullClaim(String claimName, ClaimContext ctx) {
        if (!isPresent(claimName, ctx)) return false;

        if (ctx == ClaimContext.ID_TOKEN) {
            return idTokenClaims.get(claimName) == null;
        } else if (ctx == ClaimContext.USERINFO){
            return userinfoClaims.get(claimName) == null;
        } else {
            throw new IllegalArgumentException("Invalid claim context");
        }
    }

    /**
     *
     * @param claimName
     * @param ctx Whether we ask for claim to be presented in idToken or userInfo
     * @param claimType claimType class
     * @return Claim value
     */
    @SuppressWarnings("unchecked")
    public <CLAIM_TYPE> ClaimValue<CLAIM_TYPE> getClaimValue(String claimName, ClaimContext ctx, Class<CLAIM_TYPE> claimType) {
        if (!isPresent(claimName, ctx)) return null;

        if (ctx == ClaimContext.ID_TOKEN) {
            return (ClaimValue<CLAIM_TYPE>) idTokenClaims.get(claimName);
        } else if (ctx == ClaimContext.USERINFO){
            return (ClaimValue<CLAIM_TYPE>) userinfoClaims.get(claimName);
        } else {
            throw new IllegalArgumentException("Invalid claim context");
        }
    }

    public enum ClaimContext {
        ID_TOKEN, USERINFO
    }

    /**
     * @param <CLAIM_TYPE> Specifies the type of the claim
     */
    public static class ClaimWrapper<CLAIM_TYPE> {
        @JsonAnyGetter
        @JsonAnySetter
        private Map<String, ClaimValue<CLAIM_TYPE>> claims;

        @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
        private List<VerifiedClaims> verified_claims;

        public Map<String, ClaimValue<CLAIM_TYPE>> getClaims() {
            return claims;
        }

        public void setClaims(Map<String, ClaimValue<CLAIM_TYPE>> claims) {
            this.claims = claims;
        }

        public List<VerifiedClaims> getVerified_claims() {
            return verified_claims;
        }

        public void setVerified_claims(List<VerifiedClaims> verified_claims) {
            this.verified_claims = verified_claims;
        }

        public boolean containsKey(String key) {
            if (!key.equals("verified_claims"))
                return claims != null && claims.containsKey(key);
            else return verified_claims != null;
        }

        public ClaimValue<CLAIM_TYPE> get(String key) {
            if (!key.equals("verified_claims") && claims != null)
                return claims.get(key);
            else return null;
        }
    }

    /**
     * @param <CLAIM_TYPE> Specifies the type of the claim
     */
    public static class ClaimValue<CLAIM_TYPE> {
        @JsonProperty("essential")
        private Boolean essential;

        @JsonProperty("value")
        private CLAIM_TYPE value;

        @JsonProperty("values")
        private List<CLAIM_TYPE> values;

        public Boolean getEssential() {
            return essential;
        }

        public boolean isEssential() {
            return essential != null && essential;
        }

        public void setEssential(Boolean essential) {
            this.essential = essential;
        }

        public CLAIM_TYPE getValue() {
            return value;
        }

        public void setValue(CLAIM_TYPE value) {
            this.value = value;
        }

        public List<CLAIM_TYPE> getValues() {
            return values;
        }

        public void setValues(List<CLAIM_TYPE> values) {
            this.values = values;
        }
    }

    public static class VerifiedClaims {
        private Map<String, Object> verification;

        private Map<String, Object> claims;

        public Map<String, Object> getVerification() {
            return verification;
        }

        public void setVerification(Map<String, Object> verification) {
            this.verification = verification;
        }

        public Map<String, Object> getClaims() {
            return claims;
        }

        public void setClaims(Map<String, Object> claims) {
            this.claims = claims;
        }
    }
}