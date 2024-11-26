/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;

/**
 * DTO used to define customizable parameters for a Trusted List signing
 *
 * NOTE : other basic parameters are pre-configured for a Trusted List signing
 *
 */
public class RemoteTrustedListSignatureParameters implements Serializable {

    private static final long serialVersionUID = 5459292709179313722L;

    /**
     * The signing certificate
     */
    private RemoteCertificate signingCertificate;

    /**
     * The encryption algorithm used for a signature creation by the current signing-certificate
     */
    private EncryptionAlgorithm encryptionAlgorithm;

    /**
     * The digest algorithm used to hash signed data on signing
     */
    private DigestAlgorithm digestAlgorithm;

    /**
     * The mask generation function used on signing
     */
    private MaskGenerationFunction maskGenerationFunction;

    /**
     * The B-Level parameters
     */
    private RemoteBLevelParameters bLevelParameters = new RemoteBLevelParameters();

    /**
     * The Enveloped reference Id to be used
     */
    private String referenceId;

    /**
     * The DigestAlgorithm to be used for an Enveloped-signature reference
     */
    private DigestAlgorithm referenceDigestAlgorithm;

    /**
     * The TLVersion to be signed
     */
    private Integer tlVersion;

    /**
     * Default constructor instantiating object with null values
     */
    public RemoteTrustedListSignatureParameters() {
        // empty
    }

    /**
     * Gets the signing certificate
     *
     * @return {@link RemoteCertificate}
     */
    public RemoteCertificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Sets the signing certificate
     *
     * @param signingCertificate {@link RemoteCertificate}
     */
    public void setSigningCertificate(RemoteCertificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    /**
     * Gets the encryption algorithm used by the signing-certificate
     *
     * @return {@link EncryptionAlgorithm}
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Sets the encryption algorithm used by the signing-certificate
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Gets a digest algorithm used on signing
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets a digest algorithm used on signing
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets a mask generation function, if used
     *
     * @return {@link MaskGenerationFunction}
     */
    public MaskGenerationFunction getMaskGenerationFunction() {
        return maskGenerationFunction;
    }

    /**
     * Sets a mask generation function, if used
     *
     * @param maskGenerationFunction {@link MaskGenerationFunction}
     */
    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }

    /**
     * Gets bLevel parameters
     *
     * @return {@link RemoteBLevelParameters}
     */
    public RemoteBLevelParameters getBLevelParameters() {
        return bLevelParameters;
    }

    /**
     * Sets bLevel parameters (e.g. claimed signing time, etc.)
     *
     * @param bLevelParameters {@link RemoteBLevelParameters}
     */
    public void setBLevelParameters(RemoteBLevelParameters bLevelParameters) {
        this.bLevelParameters = bLevelParameters;
    }

    /**
     * Gets an Id of an enveloped-signature reference
     *
     * @return {@link String}
     */
    public String getReferenceId() {
        return referenceId;
    }

    /**
     * Sets a custom if for an enveloped-reference creation
     *
     * NOTE: if not set, a default value will be used
     *
     * @param referenceId {@link String}
     */
    public void setReferenceId(String referenceId) {
        this.referenceId = referenceId;
    }

    /**
     * Gets a {@code DigestAlgorithm} to be used on an enveloped-signature reference creation
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getReferenceDigestAlgorithm() {
        return referenceDigestAlgorithm;
    }

    /**
     * Sets a {@code DigestAlgorithm} to be used on an enveloped-signature reference creation
     *
     * @param referenceDigestAlgorithm {@link DigestAlgorithm}
     */
    public void setReferenceDigestAlgorithm(DigestAlgorithm referenceDigestAlgorithm) {
        this.referenceDigestAlgorithm = referenceDigestAlgorithm;
    }

    /**
     * Gets the XML Trusted List Version identifier to be signed
     *
     * @return {@link Integer}
     */
    public Integer getTlVersion() {
        return tlVersion;
    }

    /**
     * Sets the XML Trusted List Version identifier to be signed.
     * This ensures the created signature corresponds to the requirements of the XML Trusted List version.
     *
     * @param tlVersion the target XML Trusted List version
     */
    public void setTlVersion(int tlVersion) {
        this.tlVersion = tlVersion;
    }

}
