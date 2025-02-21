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
package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class contains common methods for signature parameters creation for an XML Trusted List signature
 *
 */
public abstract class AbstractTrustedListSignatureParametersBuilder extends AbstractSignatureParametersBuilder<XAdESSignatureParameters> {

    /**
     * The EXCLUSIVE canonicalization shall be used
     * See TS 119 612 "B.1 The Signature element"
     */
    private static final String DEFAULT_CANONICALIZATION = CanonicalizationMethod.EXCLUSIVE;

    /** The default prefix for an enveloped signature reference id */
    private static final String DEFAULT_REFERENCE_PREFIX = "ref-enveloped-signature";

    /**
     * The XML Trusted List document
     */
    private final DSSDocument tlXmlDocument;

    /**
     * The Enveloped reference Id to use
     */
    private String referenceId;

    /**
     * The DigestAlgorithm to be used for an Enveloped reference
     */
    private DigestAlgorithm referenceDigestAlgorithm = DigestAlgorithm.SHA512;

    /**
     * The constructor to build Signature Parameters for a Trusted List signing with respect to ETSI TS 119 612
     *
     * @param signingCertificate {@link CertificateToken} to be used for a signature creation
     * @param tlXmlDocument {@link DSSDocument} Trusted List XML document to be signed
     */
    protected AbstractTrustedListSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
        super(signingCertificate);
        Objects.requireNonNull(tlXmlDocument, "XML Trusted List document cannot be null!");
        this.tlXmlDocument = tlXmlDocument;
    }

    /**
     * Sets an Enveloped Reference Id to use
     * <p>
     * Default: "ref-enveloped-signature"
     *
     * @param referenceId {@link String} reference Id
     * @return this builder
     */
    public AbstractTrustedListSignatureParametersBuilder setReferenceId(String referenceId) {
        this.referenceId = referenceId;
        return this;
    }

    /**
     * Sets an Enveloped Reference {@code DigestAlgorithm} to use
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     * @return this builder
     */
    public AbstractTrustedListSignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.referenceDigestAlgorithm = digestAlgorithm;
        return this;
    }

    @Override
    protected XAdESSignatureParameters initParameters() {
        return new XAdESSignatureParameters();
    }

    @Override
    public XAdESSignatureParameters build() {
        final XAdESSignatureParameters signatureParameters = super.build();

        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setEn319132(isEn319132());

        final List<DSSReference> references = getReferences();
        signatureParameters.setReferences(references);

        return signatureParameters;
    }

    /**
     * Gets whether the created XAdES signature shall be conformant to ETSI EN 319 132 standard
     *
     * @return TRUE if the created signature shall be conformant to ETSI EN 319 132 standard (new XAdES), FALSE otherwise
     */
    protected abstract boolean isEn319132();

    /**
     * Returns a list of ds:References to be incorporated within the signature
     *
     * @return a list of {@link DSSReference}s
     */
    protected List<DSSReference> getReferences() {
        final List<DSSReference> references = new ArrayList<>();
        DSSReference envelopedSignatureReference = getEnvelopedSignatureReference();
        references.add(envelopedSignatureReference);
        return references;
    }

    /**
     * Creates the enveloped-signature ds:Reference
     *
     * @return {@link DSSReference}
     */
    protected DSSReference getEnvelopedSignatureReference() {
        DSSReference dssReference = new DSSReference();
        if (referenceId != null) {
            dssReference.setId(referenceId);
        } else {
            dssReference.setId(DEFAULT_REFERENCE_PREFIX);
        }
        dssReference.setUri("");
        dssReference.setContents(tlXmlDocument);
        dssReference.setDigestMethodAlgorithm(referenceDigestAlgorithm);

        final List<DSSTransform> transforms = new ArrayList<>();

        EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
        transforms.add(signatureTransform);

        CanonicalizationTransform dssTransform = new CanonicalizationTransform(DEFAULT_CANONICALIZATION);
        transforms.add(dssTransform);

        dssReference.setTransforms(transforms);
        return dssReference;
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given document.
     * Thus, it verifies whether the provided document representing the XML Trusted List is conformant to the definition 
     * and the target version.
     * NOTE: this method requires 'dss-validation' module.
     *
     * @throws IllegalInputException if the provided XML Trusted List has invalid structure
     * @throws DSSException is other error occurred during the processing
     */
    public void assertConfigurationIsValid() throws IllegalInputException {
        List<String> errors;
        try {
            errors = XAdESTrustedListUtils.validateUnsignedTrustedList(tlXmlDocument, getTargetTLVersion());
        } catch (Exception e) {
            throw new DSSException(String.format("An error occurred on XML Trusted List validation : %s",
                    e.getMessage()), e);
        }
        if (Utils.isCollectionNotEmpty(errors)) {
            throw new IllegalInputException(String.format(
                    "XML Trusted List failed the validation : %s", Utils.joinStrings(errors, "; ")));
        }
    }

    /**
     * This method returns the target XML Trusted List version to be signed
     *
     * @return {@link Integer}
     */
    protected abstract Integer getTargetTLVersion();

}
