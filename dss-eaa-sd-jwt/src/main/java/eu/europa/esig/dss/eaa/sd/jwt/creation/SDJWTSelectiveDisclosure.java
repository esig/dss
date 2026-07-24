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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.eaa.common.creation.AbstractSelectiveDisclosure;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.Objects;

/**
 * Implementation of a disclosure for an SD-JWT VC token
 *
 */
public class SDJWTSelectiveDisclosure extends AbstractSelectiveDisclosure {

    private static final long serialVersionUID = -1978354313189364987L;

    /** Base64Url encoded string */
    private final String disclosure;

    /**
     * Default constructor to instantiate an SD-JWT VC disclosure from a base64url encoded disclosure string.
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

}
