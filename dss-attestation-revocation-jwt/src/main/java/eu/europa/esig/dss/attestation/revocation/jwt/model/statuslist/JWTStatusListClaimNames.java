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

/**
 * Contains a list of claim names specified within the
 * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-20.html">IETF Token Status List (TSL)</a>.
 */
public final class JWTStatusListClaimNames {

    /**
     * Utils class
     */
    private JWTStatusListClaimNames() {
        // empty
    }

    /* 5.1. Status List Token in JWT Format */

    /**
     * Data structure representing the content of a JSON-encoded Status List.
     */
    public static final String STATUS_LIST = "status_list";

    /**
     * The ttl (time to live) claim, if present, MUST specify the maximum amount of time,
     * in seconds, that the Status List Token can be cached by a consumer before a fresh
     * copy SHOULD be retrieved.
     */
    public static final String TTL = "ttl";

    /* 4.2. Status List in JSON Format */

    /**
     * JSON String that contains a URI to retrieve the Status List Aggregation for this type
     * of Referenced Token or Issuer.
     */
    public static final String AGGREGATION_URI = "aggregation_uri";

    /**
     * JSON Integer specifying the number of bits per Referenced Token in the compressed
     * byte array (lst). The allowed values for bits are 1, 2, 4, and 8.
     */
    public static final String BITS = "bits";

    /**
     * JSON String that contains the revocation values for all the Referenced Tokens it conveys statuses for.
     */
    public static final String LST = "lst";


}
