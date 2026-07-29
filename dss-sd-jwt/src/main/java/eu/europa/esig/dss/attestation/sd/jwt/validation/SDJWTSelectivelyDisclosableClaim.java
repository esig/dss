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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.SelectivelyDisclosableClaim;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import java.util.List;

/**
 * Represents an attestation Disclosure extracted from an SD-JWT token
 *
 */
public class SDJWTSelectivelyDisclosableClaim extends SelectivelyDisclosableClaim {

    private static final long serialVersionUID = -5284795899819648729L;

    /** The original disclosure value */
    private final String disclosureB64Url;

    /**
     * Default constructor
     *
     * @param disclosureB64Url {@link String} base64url encoded,
     *                         representing the original provided value of the disclosure
     */
    public SDJWTSelectivelyDisclosableClaim(final String disclosureB64Url) {
        this.disclosureB64Url = disclosureB64Url;
        parseDisclosure(disclosureB64Url);
    }

    private List<?> getDisclosureArray(final String disclosureB64Url) {
        Object disclosureObject = DSSJsonUtils.parseBase64UrlEncoded(disclosureB64Url);

        if (!(disclosureObject instanceof List<?>)) {
            throw new IllegalInputException("Invalid disclosure format! An object of a JSON Array type is expected.");
        }
        List<?> disclosureList = (List<?>) disclosureObject;
        if (disclosureList.size() != 2 && disclosureList.size() != 3) {
            throw new IllegalInputException("Invalid disclosure format! An array of 2 or 3 elements is expected.");
        }
        return disclosureList;
    }

    private void parseDisclosure(final String disclosureB64Url) {
        List<?> value = getDisclosureArray(disclosureB64Url);
        Object saltObject = value.get(0);
        if (!(saltObject instanceof String)) {
            throw new IllegalInputException("Invalid disclosure format! The first element of the array (salt) shall be of String type!");
        }
        String saltString = (String) saltObject;
        this.salt = saltString.getBytes();

        String claimName = null;
        Object claimValue;
        if (value.size() == 2) {
            // array or recursive disclosure
            claimValue = value.get(1);

        } else {
            Object claimNameObject = value.get(1);
            if (!(claimNameObject instanceof String)) {
                throw new IllegalInputException("Invalid disclosure format! The second element of the array (claim name) shall be of String type!");
            }
            claimName = (String) claimNameObject;
            claimValue = value.get(2);
        }
        this.claim = SDJWTUtils.createClaim(claimName, null, claimValue, true);
    }

    @Override
    protected Digest computeDigest(DigestAlgorithm digestAlgorithm) {
        /*
         * 4.2.3. Hashing Disclosures (draft-ietf-oauth-selective-disclosure-jwt-22)
         *
         * The input to the hash function MUST be the base64url-encoded Disclosure,
         * not the bytes encoded by the base64url string.
         */
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, disclosureB64Url.getBytes());
        return new Digest(digestAlgorithm, digestValue);
    }

}
