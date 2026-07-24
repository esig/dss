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
package eu.europa.esig.dss.attestation.revocation.cwt.model.statuslist;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cwt.CWTPayload;
import eu.europa.esig.dss.attestation.revocation.model.statuslist.StatusListPayload;

/**
 * Represents a payload of an CWT-encoded Token Status List
 *
 */
public class CWTStatusListPayload extends CWTPayload implements StatusListPayload {

    /**
     * Default constructor
     *
     * @param payload {@link CBORMap}
     */
    public CWTStatusListPayload(final CBORMap payload) {
        super(payload);
    }

    @Override
    public Number getTimeToLive() {
        return payload.getAsLong(CWTStatusListClaims.TIME_TO_LIVE.cbor());
    }

    /**
     * Gets the value of the 'status_list' (revocation list) claim that specifies the Status List
     * conforming to the structure defined in Section 4.3.
     *
     * @return {@link CBORMap}
     */
    public CBORMap getStatusList() {
        return payload.getAsMap(CWTStatusListClaims.STATUS_LIST.cbor());
    }

    @Override
    public Number getStatusListBits() {
        CBORMap statusList = getStatusList();
        if (statusList != null) {
            return statusList.getAsLong(CWTStatusListClaims.STATUS_LIST_BITS.cbor());
        }
        return null;
    }

    @Override
    public byte[] getStatusListEncoded() {
        CBORMap statusList = getStatusList();
        if (statusList != null) {
            return statusList.getAsBinaries(CWTStatusListClaims.STATUS_LIST_LST.cbor());
        }
        return null;
    }

    @Override
    public String getAggregationUri() {
        CBORMap statusList = getStatusList();
        if (statusList != null) {
            return statusList.getAsString(CWTStatusListClaims.STATUS_LIST_AGGREGATION_URI.cbor());
        }
        return null;
    }

}
