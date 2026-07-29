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

import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;

/**
 * Contains claims for processing the CWT-encoded Identifier List.
 * Please see ISO/IEC 18013-5 "12.3.6 MSO revocation".
 *
 */
public enum CWTIdentifierListClaims {

    /**
     * The identifier list map.
     */
    IDENTIFIER_LIST(65530L),

    /**
     * The time to live claim, if present, MUST specify the maximum amount of time,
     * in seconds, that the Status List Token can be cached by a consumer before a
     * fresh copy SHOULD be retrieved.
     */
    TIME_TO_LIVE(65534L),

    /* Status list entries */

    /**
     * URI to retrieve the Status List Aggregation for this type of Referenced Token
     */
    IDENTIFIER_LIST_AGGREGATION_URI("aggregation_uri"),

    /**
     * Presence of the Identifier in the IdentifierList indicates that the MSO that contains that
     * identifier in the revocation element is revoked.
     */
    IDENTIFIER_LIST_IDENTIFIERS("identifiers");

    /** Long encoded key */
    private final CBORObject cborKey;

    /**
     * Constructor with a Long key
     *
     * @param longKey long key value
     */
    CWTIdentifierListClaims(final Long longKey) {
        this.cborKey = CBORObjectFactory.toCBORObject(longKey);
    }

    /**
     * Constructor with a String key
     *
     * @param stringKey {@link String} key value
     */
    CWTIdentifierListClaims(final String stringKey) {
        this.cborKey = CBORObjectFactory.toCBORObject(stringKey);
    }

    /**
     * Gets a representation of the key in a form of a CBOR object
     *
     * @return {@link CBORObject}
     */
    public CBORObject cbor() {
        return cborKey;
    }

}
