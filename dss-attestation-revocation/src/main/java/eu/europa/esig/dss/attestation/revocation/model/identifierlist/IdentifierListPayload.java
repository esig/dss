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
package eu.europa.esig.dss.attestation.revocation.model.identifierlist;

import java.util.Date;
import java.util.List;

/**
 * Represents a payload of an Identifier List
 *
 */
public interface IdentifierListPayload {

    /**
     * Gets the value of the Subject claim identifying the principal that is the subject of the token.
     *
     * @return {@link String}
     */
    String getSubject();

    /**
     * Gets the value of the Expiration Time claim identifying the expiration time on
     * or after which the token MUST NOT be accepted for processing.
     *
     * @return {@link String}
     */
    Date getExpirationTime();

    /**
     * Gets the value of the Issued At claim identifying the time before which the token
     * MUST NOT be accepted for processing.
     *
     * @return {@link String}
     */
    Date getIssuedAt();

    /**
     * Gets the value of the Time To Live claim that specifies the maximum amount of time,
     * in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
     *
     * @return {@link String}
     */
    Number getTimeToLive();

    /**
     * Gets the value of the 'bits' (bits) of the "status_list" claim that specifies
     * the number of bits per Referenced Token in the compressed byte array (lst).
     *
     * @return {@link String}
     */
    List<byte[]> getIdentifierListIdentifiers();

    /**
     * Gets the value of the 'aggregation_uri' (Aggregation URI) of the "status_list" claim that contains
     * a URI to retrieve the Status List Aggregation for this type of Referenced Token or Issuer.
     *
     * @return {@link String}
     */
    String getAggregationUri();

}
