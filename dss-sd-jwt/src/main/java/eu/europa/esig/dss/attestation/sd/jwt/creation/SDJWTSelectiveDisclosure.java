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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AbstractSelectiveDisclosure;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import java.util.List;
import java.util.Objects;

/**
 * Implementation of a disclosure for an SD-JWT token
 *
 */
public class SDJWTSelectiveDisclosure extends AbstractSelectiveDisclosure {

    private static final long serialVersionUID = -1978354313189364987L;

    /** Base64Url encoded string */
    private final String disclosure;

    /**
     * Flag whether the disclosure has already been parsed
     * <p>
     * NOTE: This is required as SD-JWT disclosures may have no name
     */
    private boolean parsed = false;

    /**
     * Default constructor to instantiate an SD-JWT disclosure from a base64url encoded disclosure string.
     * NOTE: the class does not verify the validity of the data structure.
     *
     * @param disclosure {@link String}
     */
    public SDJWTSelectiveDisclosure(final String disclosure) {
        Objects.requireNonNull(disclosure, "Disclosure string cannot be null!");
        this.disclosure = disclosure;
    }

    /**
     * Gets the disclosure string
     *
     * @return {@link String}
     */
    public String getDisclosure() {
        return disclosure;
    }

    @Override
    protected Digest computeDigest(DigestAlgorithm digestAlgorithm) {
        /*
         * 4.2.3. Hashing Disclosures (draft-ietf-oauth-selective-disclosure-jwt-22)
         *
         * The input to the hash function MUST be the base64url-encoded Disclosure,
         * not the bytes encoded by the base64url string.
         */
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, disclosure.getBytes());
        return new Digest(digestAlgorithm, digestValue);
    }

    @Override
    protected void parse() {
        if (!parsed) {
            parseDisclosure(disclosure);
            parsed = true;
        }
    }

    private void parseDisclosure(final String disclosureB64Url) {
        List<?> disclosureArray = getDisclosureArray(disclosureB64Url);
        Object saltObject = disclosureArray.get(0);
        if (!(saltObject instanceof String)) {
            throw new IllegalInputException("Invalid disclosure format! The first element of the array (salt) shall be of String type!");
        }
        String saltString = (String) saltObject;
        this.salt = saltString.getBytes();

        if (disclosureArray.size() == 2) {
            // array or recursive disclosure
            this.value = disclosureArray.get(1);

        } else {
            Object claimNameObject = disclosureArray.get(1);
            if (!(claimNameObject instanceof String)) {
                throw new IllegalInputException("Invalid disclosure format! The second element of the array (claim name) shall be of String type!");
            }
            this.name = (String) claimNameObject;
            this.value = disclosureArray.get(2);
        }
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

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;

        SDJWTSelectiveDisclosure that = (SDJWTSelectiveDisclosure) o;
        return disclosure.equals(that.disclosure);
    }

    @Override
    public int hashCode() {
        return disclosure.hashCode();
    }

}
