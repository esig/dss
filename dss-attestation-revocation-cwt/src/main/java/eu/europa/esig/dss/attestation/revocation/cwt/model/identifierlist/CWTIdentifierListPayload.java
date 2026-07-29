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
package eu.europa.esig.dss.attestation.revocation.cwt.model.identifierlist;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cwt.CWTPayload;
import eu.europa.esig.dss.attestation.revocation.model.identifierlist.IdentifierListPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a payload of an Identifier List encoded in CWT format
 *
 */
public class CWTIdentifierListPayload extends CWTPayload implements IdentifierListPayload {

    private static final Logger LOG = LoggerFactory.getLogger(CWTIdentifierListPayload.class);

    /**
     * Default constructor
     *
     * @param payload {@link CBORMap}
     */
    public CWTIdentifierListPayload(final CBORMap payload) {
        super(payload);
    }

    @Override
    public Number getTimeToLive() {
        return payload.getAsLong(CWTIdentifierListClaims.TIME_TO_LIVE.cbor());
    }

    /**
     * Gets the value of the 'identifier_list' (identifier list) claim that specifies the Status List
     * conforming to the structure defined in "12.3.6.4 Identifier list details".
     *
     * @return {@link CBORMap}
     */
    public CBORMap getIdentifierList() {
        return payload.getAsMap(CWTIdentifierListClaims.IDENTIFIER_LIST.cbor());
    }

    @Override
    public List<byte[]> getIdentifierListIdentifiers() {
        CBORMap identifierList = getIdentifierList();
        if (identifierList != null) {
            CBORMap identifiers = identifierList.getAsMap(CWTIdentifierListClaims.IDENTIFIER_LIST_IDENTIFIERS.cbor());
            if (identifiers != null && !identifiers.isEmpty()) {
                final List<byte[]> result = new ArrayList<>();
                for (CBORObject identifier : identifiers.getValueAsMap().keySet()) {
                    if (identifier.isByteString()) {
                        result.add(identifier.getValueAsBytes());
                    } else {
                        LOG.warn("Identifier shall be a type of CBOR ByteString!");
                    }
                }
                return result;
            }
        }
        return null;
    }

    @Override
    public String getAggregationUri() {
        CBORMap statusList = getIdentifierList();
        if (statusList != null) {
            return statusList.getAsString(CWTIdentifierListClaims.IDENTIFIER_LIST_AGGREGATION_URI.cbor());
        }
        return null;
    }

}
