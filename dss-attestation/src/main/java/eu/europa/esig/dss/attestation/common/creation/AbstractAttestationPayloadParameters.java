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
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.security.PublicKey;
import java.util.Date;
import java.util.Objects;

/**
 * Abstract implementation of the attestation Payload parameters
 *
 */
public abstract class AbstractAttestationPayloadParameters implements AttestationPayloadParameters {

    /** DigestAlgorithm used to compute hashes for selectively disclosable claims  */
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    /** Date of the attestation technical validity start */
    private Date notBeforeDate;

    /** Date of the attestation technical validity end */
    private Date expirationDate;

    /** Contains the public part of the key pair used for device authentication. */
    private PublicKey deviceKey;

    /** (Optional) Contains a "status_list" as defined in IETF draft-ietf-oauth-revocation-list-20. */
    private TokenStatusList statusList;

    /* ETSI technical claims */

    /** Category of the attestation (e.g. QEAA, Pub-EAA, or other) */
    private String category;

    /** Whether the attestation is short-lived */
    private boolean shortLived;

    /** Whether the attestation is issued for a one time use */
    private boolean oneTime;

    /** The number of decoy digests that will be added */
    private int decoyDigestNumber;

    /** If the hashes in the attestation should be shuffled */
    private boolean shuffleHashes = true;

    /**
     * Default constructor
     */
    protected AbstractAttestationPayloadParameters() {
        // empty
    }

    @Override
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets digest algorithm to be used for hashes computation of selectively disclosable claims
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.digestAlgorithm = digestAlgorithm;
    }

    @Override
    public Date getNotBeforeDate() {
        return notBeforeDate;
    }

    /**
     * Sets the attestation notBefore date (technical validity start date)
     *
     * @param notBeforeDate {@link Date}
     */
    public void setNotBeforeDate(Date notBeforeDate) {
        this.notBeforeDate = notBeforeDate;
    }

    @Override
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets the attestation expiration date (technical validity end date)
     *
     * @param expirationDate {@link Date}
     */
    public void setExpirationDate(final Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    @Override
    public PublicKey getDeviceKey() {
        return deviceKey;
    }

    /**
     * Sets the public part of the key pair used for mdoc authentication.
     *
     * @param deviceKey {@link PublicKey}
     */
    public void setDeviceKey(PublicKey deviceKey) {
        this.deviceKey = deviceKey;
    }

    /**
     * Sets the certificate token used for mdoc authentication.
     * NOTE: only the public key part of the token will be represented within the payload.
     *
     * @param certificateToken {@link CertificateToken}
     */
    public void setDeviceKey(CertificateToken certificateToken) {
        if (certificateToken != null) {
            setDeviceKey(certificateToken.getPublicKey());
        }
    }

    @Override
    public TokenStatusList getStatusList() {
        return statusList;
    }

    /**
     * Sets the status_list
     *
     * @param statusList {@link TokenStatusList}
     */
    public void setStatusList(TokenStatusList statusList) {
        this.statusList = statusList;
    }

    /**
     * Sets the status_list, by specifying an index of the attestation and a revocation distribution URL
     *
     * @param index integer representing an attestation identifier within the status_list
     * @param url {@link String} where the status_list can be accessed from
     */
    public void setStatusList(int index, String url) {
        this.statusList = new TokenStatusList(index, url);
    }

    /**
     * Sets the status_list, by specifying an index of the attestation and a revocation distribution URL
     *
     * @param index integer representing an attestation identifier within the status_list
     * @param url {@link String} where the status_list can be accessed from
     * @param certificateToken {@link CertificateToken} containing the public key that signed or sealed
     *                         the top-level certificate in the x5chain element in the MSO revocation list structure
     */
    public void setStatusList(int index, String url, CertificateToken certificateToken) {
        this.statusList = new TokenStatusList(index, url, certificateToken);
    }

    @Override
    public String getCategory() {
        return category;
    }

    /**
     * Sets the attestation category URN.
     * Example: "urn:etsi:esi:eaa:eu:qualified" for QEAA, "urn:etsi:esi:eaa:eu:pub" for Pub-EAA
     *
     * @param category {@link String}
     */
    public void setCategory(String category) {
        this.category = category;
    }

    @Override
    public boolean isShortLived() {
        return shortLived;
    }

    /**
     * Sets whether the attestation is short-lived (no attestation revocation check applies)
     *
     * @param shortLived whether the attestation is short-lived
     */
    public void setShortLived(final boolean shortLived) {
        this.shortLived = shortLived;
    }

    @Override
    public boolean isOneTime() {
        return oneTime;
    }

    /**
     * Sets whether the attestation is for one time use
     *
     * @param oneTime whether the attestation is for one time use
     */
    public void setOneTime(final boolean oneTime) {
        this.oneTime = oneTime;
    }

    @Override
    public int getDecoyDigestNumber() {
        return decoyDigestNumber;
    }

    /**
     * Sets the number of decoy digest to generate
     *
     * @param decoyDigestNumber the number of decoy digest to generate
     */
    public void setDecoyDigestNumber(final int decoyDigestNumber) {
        this.decoyDigestNumber = decoyDigestNumber;
    }

    @Override
    public boolean isShuffleHashes() {
        return shuffleHashes;
    }

    /**
     * Sets whether the digests of the selectively disclosable claims are to be shuffled
     *
     * @param shuffleHashes whether the digests of the selectively disclosable claims are to be shuffled
     */
    public void setShuffleHashes(final boolean shuffleHashes) {
        this.shuffleHashes = shuffleHashes;
    }

    @Override
    public String toString() {
        return "AbstractAttestationPayloadParameters [" +
                "digestAlgorithm=" + digestAlgorithm +
                ", notBeforeDate=" + notBeforeDate +
                ", expirationDate=" + expirationDate +
                ", category='" + category + '\'' +
                ", shortLived=" + shortLived +
                ", oneTime=" + oneTime +
                ", decoyDigestNumber=" + decoyDigestNumber +
                ", shuffleHashes=" + shuffleHashes +
                ']';
    }

}
