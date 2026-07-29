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
package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * DTO containing parameters for an attestation payload generation
 *
 */
public class RemoteAttestationPayloadParameters implements Serializable {

    private static final long serialVersionUID = 6192999476014374481L;

    /** (Required) Type of the attestation to be created */
    private AttestationForm attestationForm;

    /** Pre-computed payload */
    private RemoteDocument preComputedPayload;

    /* Generic payload parameters */

    /** DigestAlgorithm used to compute hashes for selectively disclosable claims  */
    private DigestAlgorithm digestAlgorithm;
    /** Date of the attestation technical validity start */
    private Date notBeforeDate;
    /** Date of the attestation technical validity end */
    private Date expirationDate;
    /** Contains the public part of the key pair used for device authentication. */
    private RemotePublicKey deviceKey;
    /** Contains a "status_list" as defined in IETF draft-ietf-oauth-revocation-list-20. */
    private RemoteTokenStatusList statusList;
    /** Contains an "identifier_list" as defined in ISO/IEC 18013-5. */
    private RemoteIdentifierList identifierList;

    /* ETSI technical claims */

    /** Category of the attestation (e.g. QEAA, Pub-EAA, or other) */
    private String category;
    /** Whether the attestation is short-lived */
    private Boolean shortLived;
    /** Whether the attestation is issued for a one time use */
    private Boolean oneTime;
    /** The number of decoy digests that will be added */
    private Integer decoyDigestNumber;
    /** If the hashes in the attestation should be shuffled */
    private Boolean shuffleHashes;

    /* SD-JWT technical claims */

    /** attestation issuer subject */
    private String issuer;
    /** Type identifier of the embedded Verifiable Credential. */
    private String verifiableCredentialsType;
    /** Integrity metadata or cryptographic binding associated with the Verifiable Credential. */
    private DigestDTO verifiableCredentialsTypeIntegrity;

    /* Mdoc technical claims */

    /** The document type of the document and shall be identical to the DocType element in the mdoc response. */
    private String docType;
    /** Defines when the signature of the MSO is created.*/
    private Date signed;
    /** Defines date from when the signature of the MSO is valid.*/
    private Date validFrom;
    /** Defines date from when the signature of the MSO is no longer valid.*/
    private Date validUntil;
    /** Contains a date at which the issuing authority expects to re-sign the MSO (and potentially update the elements). */
    private Date expectedUpdate;

    /* Selectively disclosable claims */

    /** Contains non-selectively disclosable claims */
    private RemoteAttestationClaimParameters nonSelectivelyDisclosable;
    /** Contains selectively disclosable claims */
    private RemoteAttestationClaimParameters selectivelyDisclosable;

    /**
     * Default constructor
     */
    public RemoteAttestationPayloadParameters() {
        super();
    }

    /**
     * Constructor with attestation type provided
     *
     * @param attestationForm {@link AttestationForm}
     */
    public RemoteAttestationPayloadParameters(AttestationForm attestationForm) {
        this(attestationForm, null);
    }

    /**
     * Constructor with a pre-computed payload.
     * When used, the provided payload is used and all the configuration parameters of the class are ignored.
     *
     * @param preComputedPayload {@link RemoteDocument}
     */
    public RemoteAttestationPayloadParameters(RemoteDocument preComputedPayload) {
        this(null, preComputedPayload);
    }

    /**
     * Constructor with defined attestation type and a pre-computed payload.
     * When used, the provided payload is used and all the configuration parameters of the class are ignored.
     *
     * @param attestationForm {@link AttestationForm}
     * @param preComputedPayload {@link RemoteDocument}
     */
    public RemoteAttestationPayloadParameters(AttestationForm attestationForm, RemoteDocument preComputedPayload) {
        super();
        this.attestationForm = attestationForm;
        this.preComputedPayload = preComputedPayload;
    }

    /**
     * Gets the attestation type
     *
     * @return {@link AttestationForm}
     */
    public AttestationForm getAttestationForm() {
        return attestationForm;
    }

    /**
     * Sets the target attestation type
     *
     * @param attestationForm {@link AttestationForm}
     */
    public void setAttestationForm(AttestationForm attestationForm) {
        this.attestationForm = attestationForm;
    }

    /**
     * Gets a pre-computed payload
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getPreComputedPayload() {
        return preComputedPayload;
    }

    /**
     * Sets a pre-computed payload.
     * When used, the provided payload is used and all the configuration parameters of the class are ignored.
     *
     * @param preComputedPayload {@link RemoteDocument}
     */
    public void setPreComputedPayload(RemoteDocument preComputedPayload) {
        this.preComputedPayload = preComputedPayload;
    }

    /**
     * Gets the Digest Algorithm
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets the digest algorithm
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets the not before date
     *
     * @return {@link Date}
     */
    public Date getNotBeforeDate() {
        return notBeforeDate;
    }

    /**
     * Sets the not before date
     *
     * @param notBeforeDate {@link Date}
     */
    public void setNotBeforeDate(Date notBeforeDate) {
        this.notBeforeDate = notBeforeDate;
    }

    /**
     * Gets the expiration date
     *
     * @return {@link Date}
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Sets the expiration date
     *
     * @param expirationDate {@link Date}
     */
    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    /**
     * Gets the device key
     *
     * @return {@link RemotePublicKey}
     */
    public RemotePublicKey getDeviceKey() {
        return deviceKey;
    }

    /**
     * Sets the device key
     *
     * @param deviceKey {@link RemotePublicKey}
     */
    public void setDeviceKey(RemotePublicKey deviceKey) {
        this.deviceKey = deviceKey;
    }

    /**
     * Gets the revocation list
     *
     * @return {@link RemoteTokenStatusList}
     */
    public RemoteTokenStatusList getStatusList() {
        return statusList;
    }

    /**
     * Sets the revocation list
     *
     * @param statusList {@link RemoteTokenStatusList}
     */
    public void setStatusList(RemoteTokenStatusList statusList) {
        this.statusList = statusList;
    }

    /**
     * Gets the identifier list
     *
     * @return {@link RemoteIdentifierList}
     */
    public RemoteIdentifierList getIdentifierList() {
        return identifierList;
    }

    /**
     * Sets the identifier list
     *
     * @param identifierList {@link RemoteIdentifierList}
     */
    public void setIdentifierList(RemoteIdentifierList identifierList) {
        this.identifierList = identifierList;
    }

    /**
     * Gets the category
     *
     * @return {@link String}
     */
    public String getCategory() {
        return category;
    }

    /**
     * Sets the category
     *
     * @param category {@link String}
     */
    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * Gets whether the attestation is short-lived
     *
     * @return {@link Boolean}
     */
    public Boolean getShortLived() {
        return shortLived;
    }

    /**
     * Sets whether the attestation is short-lived
     *
     * @param shortLived {@link Boolean}
     */
    public void setShortLived(Boolean shortLived) {
        this.shortLived = shortLived;
    }

    /**
     * Gets whether the attestation is issued for a one time use
     *
     * @return {@link Boolean}
     */
    public Boolean getOneTime() {
        return oneTime;
    }

    /**
     * Sets whether the attestation is issued for a one time use
     *
     * @param oneTime {@link Boolean}
     */
    public void setOneTime(Boolean oneTime) {
        this.oneTime = oneTime;
    }

    /**
     * Gets the number of decoy digests
     *
     * @return {@link Integer}
     */
    public Integer getDecoyDigestNumber() {
        return decoyDigestNumber;
    }

    /**
     * Sets the number of decoy digests
     *
     * @param decoyDigestNumber {@link Integer}
     */
    public void setDecoyDigestNumber(Integer decoyDigestNumber) {
        this.decoyDigestNumber = decoyDigestNumber;
    }

    /**
     * Gets whether hashes should be shuffled
     *
     * @return {@link Boolean}
     */
    public Boolean getShuffleHashes() {
        return shuffleHashes;
    }

    /**
     * Sets whether hashes should be shuffled
     *
     * @param shuffleHashes {@link Boolean}
     */
    public void setShuffleHashes(Boolean shuffleHashes) {
        this.shuffleHashes = shuffleHashes;
    }

    /**
     * Gets the issuer
     *
     * @return {@link String}
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the issuer
     *
     * @param issuer {@link String}
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Gets the Verifiable Credential type
     *
     * @return {@link String}
     */
    public String getVerifiableCredentialsType() {
        return verifiableCredentialsType;
    }

    /**
     * Sets the Verifiable Credential type
     *
     * @param verifiableCredentialsType {@link String}
     */
    public void setVerifiableCredentialsType(String verifiableCredentialsType) {
        this.verifiableCredentialsType = verifiableCredentialsType;
    }

    /**
     * Gets the Verifiable Credential type integrity
     *
     * @return {@link DigestDTO}
     */
    public DigestDTO getVerifiableCredentialsTypeIntegrity() {
        return verifiableCredentialsTypeIntegrity;
    }

    /**
     * Sets the Verifiable Credential type integrity
     *
     * @param verifiableCredentialsTypeIntegrity {@link DigestDTO}
     */
    public void setVerifiableCredentialsTypeIntegrity(DigestDTO verifiableCredentialsTypeIntegrity) {
        this.verifiableCredentialsTypeIntegrity = verifiableCredentialsTypeIntegrity;
    }

    /**
     * Gets the document type
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Sets the document type
     *
     * @param docType {@link String}
     */
    public void setDocType(String docType) {
        this.docType = docType;
    }

    /**
     * Gets the signed date
     *
     * @return {@link Date}
     */
    public Date getSigned() {
        return signed;
    }

    /**
     * Sets the signed date
     *
     * @param signed {@link Date}
     */
    public void setSigned(Date signed) {
        this.signed = signed;
    }

    /**
     * Gets the date from when the signature is valid
     *
     * @return {@link Date}
     */
    public Date getValidFrom() {
        return validFrom;
    }

    /**
     * (Mdoc) Sets the date from when the signature is valid
     *
     * @param validFrom {@link Date}
     */
    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    /**
     * Gets the date from when the signature is no longer valid
     *
     * @return {@link Date}
     */
    public Date getValidUntil() {
        return validUntil;
    }

    /**
     * (Mdoc) Sets the date from when the signature is no longer valid
     *
     * @param validUntil {@link Date}
     */
    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    /**
     * Gets the expected update date
     *
     * @return {@link Date}
     */
    public Date getExpectedUpdate() {
        return expectedUpdate;
    }

    /**
     * Sets the expected update date
     *
     * @param expectedUpdate {@link Date}
     */
    public void setExpectedUpdate(Date expectedUpdate) {
        this.expectedUpdate = expectedUpdate;
    }

    /**
     * Gets the non-selectively disclosable claims
     *
     * @return {@link RemoteAttestationClaimParameters}
     */
    public RemoteAttestationClaimParameters getNonSelectivelyDisclosable() {
        return nonSelectivelyDisclosable;
    }

    /**
     * Sets the non-selectively disclosable claims
     *
     * @param nonSelectivelyDisclosable {@link RemoteAttestationClaimParameters}
     */
    public void setNonSelectivelyDisclosable(RemoteAttestationClaimParameters nonSelectivelyDisclosable) {
        this.nonSelectivelyDisclosable = nonSelectivelyDisclosable;
    }

    /**
     * Gets the selectively disclosable claims
     *
     * @return {@link RemoteAttestationClaimParameters}
     */
    public RemoteAttestationClaimParameters getSelectivelyDisclosable() {
        return selectivelyDisclosable;
    }

    /**
     * Sets the selectively disclosable claims
     *
     * @param selectivelyDisclosable {@link RemoteAttestationClaimParameters}
     */
    public void setSelectivelyDisclosable(RemoteAttestationClaimParameters selectivelyDisclosable) {
        this.selectivelyDisclosable = selectivelyDisclosable;
    }

    @Override
    public String toString() {
        return "RemoteAttestationPayloadParameters [" +
                "attestationProfile=" + attestationForm +
                ", preComputedPayload=" + preComputedPayload +
                ", digestAlgorithm=" + digestAlgorithm +
                ", notBeforeDate=" + notBeforeDate +
                ", expirationDate=" + expirationDate +
                ", deviceKey=" + deviceKey +
                ", statusList=" + statusList +
                ", identifierList=" + identifierList +
                ", category='" + category + '\'' +
                ", shortLived=" + shortLived +
                ", oneTime=" + oneTime +
                ", decoyDigestNumber=" + decoyDigestNumber +
                ", shuffleHashes=" + shuffleHashes +
                ", issuer='" + issuer + '\'' +
                ", verifiableCredentialsType='" + verifiableCredentialsType + '\'' +
                ", verifiableCredentialsTypeIntegrity=" + verifiableCredentialsTypeIntegrity +
                ", docType='" + docType + '\'' +
                ", signed=" + signed +
                ", validFrom=" + validFrom +
                ", validUntil=" + validUntil +
                ", expectedUpdate=" + expectedUpdate +
                ", nonSelectivelyDisclosable=" + nonSelectivelyDisclosable +
                ", selectivelyDisclosable=" + selectivelyDisclosable +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemoteAttestationPayloadParameters that = (RemoteAttestationPayloadParameters) object;
        return attestationForm == that.attestationForm
                && Objects.equals(preComputedPayload, that.preComputedPayload)
                && digestAlgorithm == that.digestAlgorithm
                && Objects.equals(notBeforeDate, that.notBeforeDate)
                && Objects.equals(expirationDate, that.expirationDate)
                && Objects.equals(deviceKey, that.deviceKey)
                && Objects.equals(statusList, that.statusList)
                && Objects.equals(identifierList, that.identifierList)
                && Objects.equals(category, that.category)
                && Objects.equals(shortLived, that.shortLived)
                && Objects.equals(oneTime, that.oneTime)
                && Objects.equals(decoyDigestNumber, that.decoyDigestNumber)
                && Objects.equals(shuffleHashes, that.shuffleHashes)
                && Objects.equals(issuer, that.issuer)
                && Objects.equals(verifiableCredentialsType, that.verifiableCredentialsType)
                && Objects.equals(verifiableCredentialsTypeIntegrity, that.verifiableCredentialsTypeIntegrity)
                && Objects.equals(docType, that.docType)
                && Objects.equals(signed, that.signed)
                && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil)
                && Objects.equals(expectedUpdate, that.expectedUpdate)
                && Objects.equals(nonSelectivelyDisclosable, that.nonSelectivelyDisclosable)
                && Objects.equals(selectivelyDisclosable, that.selectivelyDisclosable);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(attestationForm);
        result = 31 * result + Objects.hashCode(preComputedPayload);
        result = 31 * result + Objects.hashCode(digestAlgorithm);
        result = 31 * result + Objects.hashCode(notBeforeDate);
        result = 31 * result + Objects.hashCode(expirationDate);
        result = 31 * result + Objects.hashCode(deviceKey);
        result = 31 * result + Objects.hashCode(statusList);
        result = 31 * result + Objects.hashCode(identifierList);
        result = 31 * result + Objects.hashCode(category);
        result = 31 * result + Objects.hashCode(shortLived);
        result = 31 * result + Objects.hashCode(oneTime);
        result = 31 * result + Objects.hashCode(decoyDigestNumber);
        result = 31 * result + Objects.hashCode(shuffleHashes);
        result = 31 * result + Objects.hashCode(issuer);
        result = 31 * result + Objects.hashCode(verifiableCredentialsType);
        result = 31 * result + Objects.hashCode(verifiableCredentialsTypeIntegrity);
        result = 31 * result + Objects.hashCode(docType);
        result = 31 * result + Objects.hashCode(signed);
        result = 31 * result + Objects.hashCode(validFrom);
        result = 31 * result + Objects.hashCode(validUntil);
        result = 31 * result + Objects.hashCode(expectedUpdate);
        result = 31 * result + Objects.hashCode(nonSelectivelyDisclosable);
        result = 31 * result + Objects.hashCode(selectivelyDisclosable);
        return result;
    }

}
