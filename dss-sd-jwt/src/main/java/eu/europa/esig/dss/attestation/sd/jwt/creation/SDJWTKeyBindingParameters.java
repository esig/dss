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

import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.Date;

/**
 * Implementation of {@link KeyBindingParameters} for SD-JWT-KB
 */
public class SDJWTKeyBindingParameters implements KeyBindingParameters {

    /** DigestAlgorithm used to compute the hash for the key binding signature, it should the same value as the digest algorithm of the attestation */
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    /** Issuance time of the key binding signature */
    private Date issuanceTime;

    /** Intended receiver of the key binding */
    private String audience;

    /** Nonce of the key binding */
    private String nonce;

    /**
     * Default constructor
     */
    public SDJWTKeyBindingParameters() {
        //empty
    }

    /**
     * Gets the digest algorithm used to compute the hash for the key binding signature
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets the digest algorithm used to compute the hash for the key binding signature
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets the issuance time of the key binding signature
     *
     * @return {@link Date}
     */
    public Date getIssuanceTime() {
        return issuanceTime;
    }

    /**
     * Sets the issuance time of the key binding signature
     *
     * @param issuanceTime {@link Date}
     */
    public void setIssuanceTime(final Date issuanceTime) {
        this.issuanceTime = issuanceTime;
    }

    /**
     * Gets the intended receiver of the key binding
     *
     * @return {@link String}
     */
    public String getAudience() {
        return audience;
    }

    /**
     * Sets the intended receiver of the key binding
     *
     * @param audience {@link String}
     */
    public void setAudience(final String audience) {
        this.audience = audience;
    }

    /**
     * Gets the nonce of the key binding
     *
     * @return {@link String}
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Sets the nonce of the key binding
     *
     * @param nonce {@link String}
     */
    public void setNonce(final String nonce) {
        this.nonce = nonce;
    }

}
