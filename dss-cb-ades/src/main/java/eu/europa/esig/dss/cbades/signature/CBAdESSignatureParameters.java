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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;

import java.util.Objects;

/**
 * The parameters to create/extend a CB-AdES signature
 * 
 */
public class CBAdESSignatureParameters extends AbstractSignatureParameters<CBAdESTimestampParameters> {

    private static final long serialVersionUID = 4741826099908546457L;

    /**
     * Enumeration defining ways to embed the 'x5chain' header into a COSE signature
     */
    public enum X5ChainHeaderPlacement {
        /**
         * Insert the 'x5chain' header within the protected headers map (signed)
         */
        protectedHeader,
        /**
         * Insert the 'x5chain' header within the unprotected headers map (unsigned)
         */
        unprotectedHeader,
        /**
         * Insert the 'x5chain' header as an item within the 'uHeaders' unprotected header array (unsigned)
         */
        uHeaders,
    }

    /**
     * Defines if certificate chain binaries must be included in the signature ('x5chain' header)
     * <p>
     * DEFAULT: TRUE (the certificate chain header will be included into the signature)
     */
    private boolean includeCertificateChain = true;

    /**
     * Defines the element within COSE signature to embed the 'x5chain' header parameter into.
     * Applies when the {@code includeCertificateChain} parameter is enabled.
     * DEFAULT: X5ChainHeaderPlacement.protectedHeader ('x5chain' is to be included within the protected header)
     */
    private X5ChainHeaderPlacement x5ChainHeaderPlacement;

    /**
     * Defines whether the thumbprints of the whole X.509 certificate chain should be included, using a 'x5ts' signed header.
     * When certificate chain is not provided, only the signing-certificate will be included to the chain.
     * When disabled, creates a 'x5t' signed header with only signing-certificate's thumbprint provided.
     * DEFAULT : FALSE (the 'x5t' signed header with a signing-certificate's thumbprint to be included)
     */
    private boolean includeCertificateChainThumbprints = false;

    /**
     * Defines a MimeType of the signature to be created, to be provided within a signed header ('typ' attribute)
     */
    private String signatureType;

    /**
     * This property defines whether a 'kid' (key identifier) header parameter should be added to a signed header.
     * <p>
     * NOTE: a signing certificate shall be provided to embed the 'kid' header
     * <p>
     * DEFAULT: TRUE ('kid' header parameter is included into the signed header, provided that
     *           the signing-certificate is defined within the signature parameters).
     */
    private boolean includeKeyIdentifier = true;

    /**
     * The value of the 'kid' (key identifier) parameter to be embedded within the protected header of the signature
     * <p>
     * DEFAULT: when not defined and {@code includeKeyIdentifier} is enabled, the value of the embedded 'kid'
     *          protected header corresponds to the IssuerSerial of the signing-certificate.
     */
    private byte[] keyIdentifier;

    /**
     * This property defines a value for the 'x5u' signed header parameter (see RFC 9360).
     * The value shall refer to a URI where the X.509 public key certificate or certificate chain
     * corresponding to the key used to digitally sign the COSE can be retrieved from.
     * <p>
     * NOTE: use methods {@code #setSigningCertificate} and {@code #includeCertificateChain}
     *       to disable encapsulation of the signing certificate and certificate chain binaries
     * <p>
     * DEFAULT: NULL (the 'x5u' header parameter is not included)
     */
    private String x509Url;

    /**
     * The DigestAlgorithm used to create a reference to a signing certificate, namely 'x5t' signed header
     */
    private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA512;

    /**
     * Defines the COSE structure, whether to allow multiple signers (COSE_SIGN) or preserve only one signer (COSE_SIGN1)
     * Default : COSEStructureType.COSE_SIGN (allows multiple signature incorporation)
     */
    private COSEStructureType coseStructureType = COSEStructureType.COSE_SIGN;

    /**
     * Defines the encoding of the signature structure as either tagged (TRUE) or untagged (FALSE),
     * depending on the context it will be used in.
     * <p>
     * Default: TRUE (tagged signature structure is used, i.e. COSE_Sign_Tagged or COSE_Sign1_Tagged)
     */
    private Boolean tagged;

    /**
     * Externally supplied data from the application, carried outside the COSE signature structure,
     * but used as a part of a signature computation.
     * <p>
     * NOTE: this field is optional, but used as a part of DataToBeSigned computation, when provided.
     * WARN: When present on a signature creation, the data object shall be supplied on signature validation too.
     */
    private DSSDocument externallySuppliedData;

    /**
     * Defines a used 'sigD' mechanism for a detached signature
     */
    private SigDMechanism sigDMechanism;

    /**
     * Default constructor instantiating object with default parameters
     */
    public CBAdESSignatureParameters() {
        // empty
    }

    @Override
    public void setSignatureLevel(SignatureLevel signatureLevel) {
        if (signatureLevel == null || SignatureForm.CBAdES != signatureLevel.getSignatureForm()) {
            throw new IllegalArgumentException("Only CBAdES form is allowed !");
        }
        super.setSignatureLevel(signatureLevel);
    }

    @Override
    public CBAdESTimestampParameters getContentTimestampParameters() {
        if (contentTimestampParameters == null) {
            contentTimestampParameters = new CBAdESTimestampParameters();
        }
        return contentTimestampParameters;
    }

    @Override
    public CBAdESTimestampParameters getSignatureTimestampParameters() {
        if (signatureTimestampParameters == null) {
            signatureTimestampParameters = new CBAdESTimestampParameters();
        }
        return signatureTimestampParameters;
    }

    @Override
    public CBAdESTimestampParameters getArchiveTimestampParameters() {
        if (archiveTimestampParameters == null) {
            archiveTimestampParameters = new CBAdESTimestampParameters();
        }
        return archiveTimestampParameters;
    }

    /**
     * Defines if complete certificate chain binaries must be included into the COSE signature ('x5chain' header)
     *
     * @return TRUE if the certificate chain must be included, FALSE otherwise
     */
    public boolean isIncludeCertificateChain() {
        return includeCertificateChain;
    }

    /**
     * Sets if complete certificate chain binaries must be included into the 'x5chain' header.
     * NOTE: for a corresponding placement position, please see the {@code x5ChainHeaderPlacement} parameter.
     * Default: TRUE (the complete binaries will be included into the COSE signature)
     *
     * @param includeCertificateChain if the certificate chain binaries must be included into the COSE signature
     */
    public void setIncludeCertificateChain(boolean includeCertificateChain) {
        this.includeCertificateChain = includeCertificateChain;
    }

    /**
     * Gets the placement of the 'x5chain' header parameter
     *
     * @return {@link X5ChainHeaderPlacement}
     */
    public X5ChainHeaderPlacement getX5ChainHeaderPlacement() {
        return x5ChainHeaderPlacement;
    }

    /**
     * Sets the placement of the 'x5chain' header parameter within the COSE signature structure.
     * Applies when the {@code includeCertificateChain} parameter is enabled.
     * DEFAULT: X5ChainHeaderPlacement.protectedHeader ('x5chain' is to be included within the protected header)
     *
     * @param x5ChainHeaderPlacement {@link X5ChainHeaderPlacement}
     */
    public void setX5ChainHeaderPlacement(X5ChainHeaderPlacement x5ChainHeaderPlacement) {
        this.x5ChainHeaderPlacement = x5ChainHeaderPlacement;
    }

    /**
     * Returns whether the thumbprints of the whole certificate chain should be included in the signature's
     * protected header using the 'x5ts' signed header.
     *
     * @return TRUE if the thumbprints of certificate chain to be included, FALSE otherwise
     */
    public boolean isIncludeCertificateChainThumbprints() {
        return includeCertificateChainThumbprints;
    }

    /**
     * Sets whether the thumbprints of the whole certificate chain should be included in the signature's
     * protected header using the 'x5ts' signed header.
     * When enabled, adds the signing-certificate at the first position, with other certificates following
     * in the provided order.
     * When disabled, creates a 'x5t' signed header with only signing-certificate's thumbprint provided.
     * <p>
     * DEFAULT : FALSE (the 'x5t' signed header with a signing-certificate's thumbprint to be included)
     *
     * @param includeCertificateChainThumbprints whether the thumbprints of the certificate chain should be included
     */
    public void setIncludeCertificateChainThumbprints(boolean includeCertificateChainThumbprints) {
        this.includeCertificateChainThumbprints = includeCertificateChainThumbprints;
    }

    /**
     * Gets the MimeType of the signature, to be incorporated in the signed header ('typ' attribute)
     *
     * @return {@link String}
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Sets the MimeType of the signature to be incorporated within the signed header ('typ' attribute)
     *
     * @param signatureType {@link String}
     */
    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Returns whether a 'kid' (key identifier) header parameter should be created
     *
     * @return TRUE if the 'kid' should be created, FALSE otherwise
     */
    public boolean isIncludeKeyIdentifier() {
        return includeKeyIdentifier;
    }

    /**
     * Sets whether a 'kid' (key identifier) header parameter should be created within a signed header,
     * provided that a signing-certificate is defined within the signature parameters.
     * <p>
     * DEFAULT : TRUE (the 'kid' header parameter is created)
     *
     * @param includeKeyIdentifier identifies whether 'kid' should be created (when a signing-certificate is provided)
     */
    public void setIncludeKeyIdentifier(boolean includeKeyIdentifier) {
        this.includeKeyIdentifier = includeKeyIdentifier;
    }

    /**
     * Gets the value of the 'kid' (key identifier) protected header parameter.
     *
     * @return byte array
     */
    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * Sets the 'kid' value to be incorporated within the signature's protected header.
     * <p>
     * DEFAULT: when not defined and {@code includeKeyIdentifier} is enabled, the value of the embedded 'kid'
     *          protected header corresponds to the IssuerSerial of the signing-certificate.
     *
     * @param keyIdentifier byte array
     */
    public void setKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    /**
     * Returns the value of the 'x5u' (X.509 URL) header parameter if present
     *
     * @return {@link String}
     */
    public String getX509Url() {
        return x509Url;
    }

    /**
     * Sets the value for the 'x5u' (X.509 URL) signed header parameter (see RFC 9360).
     * The value shall refer to a URI where the X.509 public key certificate or certificate chain
     * corresponding to the key used to digitally sign the COSE can be retrieved from.
     * <p>
     * NOTE: use methods {@code #setSigningCertificate} and {@code #includeCertificateChain}
     *       to disable encapsulation of the signing certificate and certificate chain binaries (included by default).
     * <p>
     * DEFAULT: NULL (the 'x5u' (X.509 URL) header parameter is not included)
     *
     * @param x509Url {@link String} value of 'x5u' header parameter
     */
    public void setX509Url(String x509Url) {
        this.x509Url = x509Url;
    }

    /**
     * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm)}.
     *
     * @return {@link DigestAlgorithm} to be used for signing certificate digest representation
     */
    public DigestAlgorithm getSigningCertificateDigestMethod() {
        return signingCertificateDigestMethod;
    }

    /**
     * The digest method indicates the digest algorithm to be used to calculate the certificate digest
     * to define a signing certificate (RFC 9360 'x5t' signed header)
     * Default: DigestAlgorithm.SHA512
     *
     * @param signingCertificateDigestMethod {@link DigestAlgorithm} to be used
     */
    public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
        Objects.requireNonNull(signingCertificateDigestMethod, "SigningCertificateDigestMethod cannot be null!");
        this.signingCertificateDigestMethod = signingCertificateDigestMethod;
    }

    /**
     * Gets the COSE structure type
     *
     * @return {@link COSEStructureType}
     */
    public COSEStructureType getCoseStructureType() {
        return coseStructureType;
    }

    /**
     * Sets the COSE structure type as per RFC 9052 "4. Signing Objects".
     * - COSE_SIGN is used to create a signature format with multiple signers;
     * - COSE_SIGN1 is used to create a signature format with one and only one signer.
     * NOTE: unlike JWS serialization types, no type conversion is allowed for CBOR signatures.
     * Default : COSEStructureType.COSE_SIGN (multiple signers are allowed)
     *
     * @param coseStructureType {@link COSEStructureType}
     */
    public void setCoseStructureType(COSEStructureType coseStructureType) {
        Objects.requireNonNull(coseStructureType, "COSEStructureType cannot be null!");
        this.coseStructureType = coseStructureType;
    }

    /**
     * Gets whether a tagged signature structure is used
     *
     * @return TRUE if a tagged signature structure is used, FALSE for untagged
     */
    public Boolean isTagged() {
        return tagged;
    }

    /**
     * Sets the encoding of the signature structure on signature creation as either tagged (TRUE) or untagged (FALSE),
     * depending on the context it will be used in.
     * <p>
     * Default: TRUE (tagged signature structure is used, i.e. COSE_Sign_Tagged or COSE_Sign1_Tagged)
     * <p>
     * NOTE: the value is ignored on signing or augmentation of existing signature structure.
     *       The original encoding type is used.
     *
     * @param tagged whether the tagged signature structure shall be used
     */
    public void setTagged(Boolean tagged) {
        this.tagged = tagged;
    }

    /**
     * Gets the externally supplied data.
     * NOTE: the data is carried outside the COSE signature structure, but used on signature creation and validation.
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getExternallySuppliedData() {
        return externallySuppliedData;
    }

    /**
     * Sets an optional externally supplied data, carried outside the COSE signature structure,
     * but used as a part of a signature computation.
     * <p>
     * NOTE: this data is used as a part of DataToBeSigned computation, when provided.
     * WARN: When present on a signature creation, the data object shall be supplied on signature validation too.
     *
     * @param externallySuppliedData {@link DSSDocument}
     */
    public void setExternallySuppliedData(DSSDocument externallySuppliedData) {
        this.externallySuppliedData = externallySuppliedData;
    }

    /**
     * Returns a sigD mechanism to use
     *
     * @return {@link SigDMechanism}
     */
    public SigDMechanism getSigDMechanism() {
        return sigDMechanism;
    }

    /**
     * Sets sigD mechanism to use for a Detached signature
     *
     * @param sigDMechanism {@link SigDMechanism}
     */
    public void setSigDMechanism(SigDMechanism sigDMechanism) {
        this.sigDMechanism = sigDMechanism;
    }

}
