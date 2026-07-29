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
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * DTO for key binding signature parameters
 *
 */
public class RemoteKeyBindingParameters implements Serializable {

    private static final long serialVersionUID = 7115773287145650462L;

    /** (Required) Type of the attestation to be created */
    private AttestationForm attestationForm;

    /* SD-JWT parameters */

    /** DigestAlgorithm used to compute the hash for the key binding signature, it should the same value as the digest algorithm of the attestation */
    private DigestAlgorithm digestAlgorithm;

    /** Issuance time of the key binding signature */
    private Date issuanceTime;

    /** Intended receiver of the key binding */
    private String audience;

    /** Nonce of the key binding */
    private String nonce;

    /* Mdoc parameters */

    /** The session transcript to use for the creation of the key binding signature */
    private RemoteDocument sessionTranscript;

    /** Doc type to use for the key binding signature, the value should be the same as in attestation */
    private String docType;

    /** The list of device signed data elements */
    private List<ClaimDTO> deviceSignedDataElements;

    /**
     * Default constructor
     */
    public RemoteKeyBindingParameters() {
        super();
    }

    /**
     * Constructor with attestation type provided
     *
     * @param attestationForm {@link AttestationForm}
     */
    public RemoteKeyBindingParameters(AttestationForm attestationForm) {
        this.attestationForm = attestationForm;
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
     * Gets the digest algorithm used to compute the hash for the key binding signature
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * (SD-JWT) Sets the digest algorithm used to compute the hash for the key binding signature
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
     * (SD-JWT) Sets the issuance time of the key binding signature
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
     * (SD-JWT) Sets the intended receiver of the key binding
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
     * (SD-JWT) Sets the nonce of the key binding
     *
     * @param nonce {@link String}
     */
    public void setNonce(final String nonce) {
        this.nonce = nonce;
    }

    /**
     * Gets the session transcript to use for the creation of the key binding signature
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getSessionTranscript() {
        return sessionTranscript;
    }

    /**
     * (Mdoc) Sets the session transcript to use for the creation of the key binding signature
     *
     * @param sessionTranscript {@link RemoteDocument}
     */
    public void setSessionTranscript(final RemoteDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
    }

    /**
     * Gets the document type to use for the key binding signature
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * (Mdoc) Sets the document type to use for the key binding signature
     *
     * @param docType {@link String}
     */
    public void setDocType(final String docType) {
        this.docType = docType;
    }

    /**
     * Gets the list of device signed data elements
     *
     * @return {@link List<ClaimDTO>}
     */
    public List<ClaimDTO> getDeviceSignedDataElements() {
        return deviceSignedDataElements;
    }

    /**
     * (Mdoc) Sets the list of device signed data elements
     *
     * @param deviceSignedDataElements {@link List<ClaimDTO>}
     */
    public void setDeviceSignedDataElements(final List<ClaimDTO> deviceSignedDataElements) {
        this.deviceSignedDataElements = deviceSignedDataElements;
    }

    @Override
    public String toString() {
        return "RemoteKeyBindingParameters [" +
                "attestationProfile=" + attestationForm +
                ", digestAlgorithm=" + digestAlgorithm +
                ", issuanceTime=" + issuanceTime +
                ", audience='" + audience + '\'' +
                ", nonce='" + nonce + '\'' +
                ", sessionTranscript=" + sessionTranscript +
                ", docType='" + docType + '\'' +
                ", deviceSignedDataElements=" + deviceSignedDataElements +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        RemoteKeyBindingParameters that = (RemoteKeyBindingParameters) object;
        return attestationForm == that.attestationForm
                && digestAlgorithm == that.digestAlgorithm
                && Objects.equals(issuanceTime, that.issuanceTime)
                && Objects.equals(audience, that.audience)
                && Objects.equals(nonce, that.nonce)
                && Objects.equals(sessionTranscript, that.sessionTranscript)
                && Objects.equals(docType, that.docType)
                && Objects.equals(deviceSignedDataElements, that.deviceSignedDataElements);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(attestationForm);
        result = 31 * result + Objects.hashCode(digestAlgorithm);
        result = 31 * result + Objects.hashCode(issuanceTime);
        result = 31 * result + Objects.hashCode(audience);
        result = 31 * result + Objects.hashCode(nonce);
        result = 31 * result + Objects.hashCode(sessionTranscript);
        result = 31 * result + Objects.hashCode(docType);
        result = 31 * result + Objects.hashCode(deviceSignedDataElements);
        return result;
    }

}
