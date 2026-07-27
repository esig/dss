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
package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.security.PublicKey;
import java.util.Date;

/**
 * Contains configuration of the claims to be incorporated within an attestation Payload
 *
 */
public interface AttestationPayloadParameters {

    /**
     * Digest algorithm used to compute hashes for selectively disclosable claims.
     * Default : DigestAlgorithm.SHA256
     *
     * @return {@link DigestAlgorithm}
     */
    DigestAlgorithm getDigestAlgorithm();

    /**
     * Gets the attestation notBefore date
     *
     * @return {@link Date}
     */
    Date getNotBeforeDate();

    /**
     * Gets the attestation expiration date
     *
     * @return {@link Date}
     */
    Date getExpirationDate();

    /**
     * Gets the public part of the key pair used for mdoc authentication.
     *
     * @return {@link PublicKey}
     */
    PublicKey getDeviceKey();

    /**
     * Gets the status_list
     *
     * @return {@link TokenStatusList}
     */
    TokenStatusList getStatusList();

    /**
     * Gets the attestation category URN
     *
     * @return {@link String}
     */
    String getCategory();

    /**
     * Gets whether the attestation is short-lived (no attestation revocation check applies)
     *
     * @return whether the attestation is short-lived
     */
    boolean isShortLived();

    /**
     * Gets whether the attestation is for one time use
     *
     * @return whether the attestation is for one time use
     */
    boolean isOneTime();

    /**
     * Gets the number of decoy digest to generate
     *
     * @return the number of decoy digest to generate
     */
    int getDecoyDigestNumber();

    /**
     * Gets whether the digests of the selectively disclosable claims are to be shuffled
     *
     * @return TRUE if the hashes of the selectively disclosable claims are to be shuffled, FALSE otherwise
     */
    boolean isShuffleHashes();

}
