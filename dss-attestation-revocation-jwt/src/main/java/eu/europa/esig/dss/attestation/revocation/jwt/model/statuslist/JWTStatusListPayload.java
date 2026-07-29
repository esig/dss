/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.attestation.revocation.jwt.model.statuslist;

import eu.europa.esig.dss.attestation.revocation.model.statuslist.StatusListPayload;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.jwt.JWTPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Represents a payload of a Token Status List (TLS), as defined in
 * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-20.html">IETF Token Status List (TSL)</a>.
 */
public class JWTStatusListPayload extends JWTPayload implements StatusListPayload {

    private static final Logger LOG = LoggerFactory.getLogger(JWTStatusListPayload.class);

    /**
     * Default constructor
     *
     * @param payload map
     */
    public JWTStatusListPayload(final Map<String, Object> payload) {
        super(payload);
    }

    /**
     * Gets the value of the 'ttl' (time to live) claim that specifies the maximum amount of time,
     * in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
     *
     * @return {@link Number}
     */
    @Override
    public Number getTimeToLive() {
        return getAsNumber(JWTStatusListClaimNames.TTL);
    }

    /**
     * Gets the value of the 'status_list' (revocation list) claim that specifies the Status List
     * conforming to the structure defined in Section 4.2.
     *
     * @return {@link Map}
     */
    public Map<?, ?> getStatusList() {
        return getAsMap(JWTStatusListClaimNames.STATUS_LIST);
    }

    @Override
    public Number getStatusListBits() {
        Map<?, ?> statusList = getStatusList();
        if (statusList != null) {
            return DSSJsonUtils.getAsNumber(statusList, JWTStatusListClaimNames.BITS);
        }
        return null;
    }

    @Override
    public byte[] getStatusListEncoded() {
        Map<?, ?> statusList = getStatusList();
        if (statusList != null) {
            String lst = DSSJsonUtils.getAsString(statusList, JWTStatusListClaimNames.LST);
            if (lst == null) {
                LOG.warn("The 'lst' claim of the 'status_list' is not present or null!");
                return null;
            }
            if (!DSSJsonUtils.isBase64UrlEncoded(lst)) {
                LOG.warn("The value of the 'lst' claim of the 'status_list' is not base64url-encoded!");
                return null;
            }
            try {
                return DSSJsonUtils.fromBase64Url(lst);
            } catch (Exception e) {
                LOG.warn("Unable to decode 'lst' string value : {}", e.getMessage(), e);
            }
        }
        return null;
    }

    @Override
    public String getAggregationUri() {
        Map<?, ?> statusList = getStatusList();
        if (statusList != null) {
            return DSSJsonUtils.getAsString(statusList, JWTStatusListClaimNames.AGGREGATION_URI);
        }
        return null;
    }

}
