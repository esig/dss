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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSBuilder;
import eu.europa.esig.dss.cms.CMSSignerInfoGeneratorBuilder;
import eu.europa.esig.dss.cms.operator.CustomContentSigner;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.operator.ContentSigner;

import java.util.Objects;

/**
 * This class is used to build an instance of {@code eu.europa.esig.dss.cms.CMS}
 * for a CAdES Baseline B creation
 *
 */
public class CMSForCAdESBuilderHelper {

    /** The document to be signed by the CAdES signature */
    protected final DSSDocument documentToSign;

    /** Signature parameters used on the signature creation */
    protected final CAdESSignatureParameters signatureParameters;

    /** Content signer used for the signature creation */
    protected final ContentSigner contentSigner;

    /** Original CMS, when available */
    private CMS originalCMS;

    /** Certificate source containing trust anchors */
    private CertificateSource trustedCertificateSource;

    /** Defines whether the unsigned attributes should be included to a generated SignerInfoGenerator */
    private boolean includeUnsignedAttributes;

    /** Cached instance of a CAdES profile */
    private CAdESLevelBaselineB cadesProfile;

    /**
     * Default constructor
     *
     * @param documentToSign {@link DSSDocument}
     * @param signatureParameters {@link CAdESSignatureParameters}
     * @param contentSigner {@link CustomContentSigner}
     */
    public CMSForCAdESBuilderHelper(final DSSDocument documentToSign, final CAdESSignatureParameters signatureParameters,
                                    final ContentSigner contentSigner) {
        Objects.requireNonNull(documentToSign, "documentToSign cannot be null!");
        Objects.requireNonNull(signatureParameters, "signatureParameters cannot be null!");
        Objects.requireNonNull(contentSigner, "contentSigner cannot be null!");
        this.documentToSign = documentToSign;
        this.signatureParameters = signatureParameters;
        this.contentSigner = contentSigner;
    }

    /**
     * Sets original CMS, when available
     *
     * @param originalCMS {@link CMS}
     * @return this {@link CMSForCAdESBuilderHelper}
     */
    public CMSForCAdESBuilderHelper setOriginalCMS(CMS originalCMS) {
        this.originalCMS = originalCMS;
        return this;
    }

    /**
     * Sets trusted certificate source
     *
     * @param trustedCertificateSource {@link CertificateSource}
     * @return this {@link CMSForCAdESBuilderHelper}
     */
    public CMSForCAdESBuilderHelper setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
        this.trustedCertificateSource = trustedCertificateSource;
        return this;
    }

    /**
     * Sets whether the unsigned attributes should be included into the generated SignerInfoGenerator
     *
     * @param includeUnsignedAttributes whether the unsigned attributes should be included
     * @return this {@link CMSForCAdESBuilderHelper}
     */
    public CMSForCAdESBuilderHelper setIncludeUnsignedAttributes(boolean includeUnsignedAttributes) {
        this.includeUnsignedAttributes = includeUnsignedAttributes;
        return this;
    }

    /**
     * Creates a CMS using the {@code contentSigner}
     *
     * @return {@link CMS}
     */
    public CMS createCMS() {
        Objects.requireNonNull(contentSigner, "contentSigner cannot be null!");
        final CMSBuilder cmsBuilder = initCMSBuilder();
        final SignerInfoGenerator signerInfoGenerator = createSignerInfoGenerator();
        return cmsBuilder.createCMS(signerInfoGenerator, documentToSign);
    }

    /**
     * Creates a SignerInfoGenerator for a CAdES creation
     *
     * @return {@link SignerInfoGenerator}
     */
    public SignerInfoGenerator createSignerInfoGenerator() {
        assertSignatureParametersValid();

        AttributeTable signedAttributes = initSignedAttributesTable();
        AttributeTable unsignedAttributes = initUnsignedAttributesTable();

        CMSSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = createCMSSignerInfoGeneratorBuilder(signedAttributes, unsignedAttributes);
        return signerInfoGeneratorBuilder.build(documentToSign, contentSigner);
    }

    /**
     * Creates a signed attributes table for the CAdES Baseline B creation
     *
     * @return {@link AttributeTable}
     */
    protected AttributeTable initSignedAttributesTable() {
        final CAdESLevelBaselineB profile = getCAdESProfile();
        return profile.getSignedAttributes(signatureParameters);
    }

    /**
     * Creates an unsigned attributes table for the CAdES Baseline B creation
     *
     * @return {@link AttributeTable}
     */
    protected AttributeTable initUnsignedAttributesTable() {
        if (includeUnsignedAttributes) {
            final CAdESLevelBaselineB profile = getCAdESProfile();
            return profile.getUnsignedAttributes();
        }
        return null;
    }

    /**
     * Gets an instance of {@code CAdESLevelBaselineB} used for the signed and unsigned attributes table creation
     *
     * @return {@link CAdESLevelBaselineB}
     */
    protected CAdESLevelBaselineB getCAdESProfile() {
        if (cadesProfile == null) {
            cadesProfile = initCAdESProfile();
        }
        return cadesProfile;
    }

    /**
     * Instantiates a new {@code CAdESLevelBaselineB}
     *
     * @return {@link CAdESLevelBaselineB}
     */
    protected CAdESLevelBaselineB initCAdESProfile() {
        return new CAdESLevelBaselineB(documentToSign);
    }

    /**
     * Creates and configures a {@code CMSSignerInfoGeneratorBuilder} to be used for a SignerInfo creation
     *
     * @param signedAttributes {@link AttributeTable} representing the signed attributes
     * @param unsignedAttributes {@link AttributeTable} representing the unsigned attributes
     * @return {@link CMSSignerInfoGeneratorBuilder}
     */
    protected CMSSignerInfoGeneratorBuilder createCMSSignerInfoGeneratorBuilder(AttributeTable signedAttributes,
                                                                                AttributeTable unsignedAttributes) {
        return initCMSSignerInfoGeneratorBuilder()
                .setSigningCertificate(signatureParameters.getSigningCertificate())
                .setDigestAlgorithm(signatureParameters.getReferenceDigestAlgorithm())
                .setSignedAttributes(signedAttributes)
                .setUnsignedAttributes(unsignedAttributes);
    }

    /**
     * Creates a new instance of {@code CMSSignerInfoGeneratorBuilder}
     *
     * @return {@link CMSSignerInfoGeneratorBuilder}
     */
    protected CMSSignerInfoGeneratorBuilder initCMSSignerInfoGeneratorBuilder() {
        return new CMSSignerInfoGeneratorBuilder();
    }

    /**
     * Verifies validity of the signature parameters configuration
     */
    protected void assertSignatureParametersValid() {
        if (signatureParameters.getSigningCertificate() == null && !signatureParameters.isGenerateTBSWithoutCertificate()) {
            throw new IllegalArgumentException("Signing-certificate is not provided! " +
                    "Use #setGenerateWithoutCertificates(true) method.");
        }
    }

    /**
     * Instantiates a {@code CMSBuilder} for the CMS creation
     *
     * @return {@link CMSBuilder}
     */
    protected CMSBuilder initCMSBuilder() {
        return new CMSBuilder()
                .setSigningCertificate(signatureParameters.getSigningCertificate())
                .setCertificateChain(signatureParameters.getCertificateChain())
                .setGenerateWithoutCertificates(signatureParameters.isGenerateTBSWithoutCertificate())
                .setTrustAnchorBPPolicy(signatureParameters.bLevel().isTrustAnchorBPPolicy())
                .setTrustedCertificateSource(trustedCertificateSource)
                .setEncapsulate(isEncapsulateSignerData())
                .setOriginalCMS(originalCMS);
    }

    /**
     * Gets whether the signed data shall be encapsulated
     *
     * @return TRUE if the signed data shall be encapsulated, FALSE otherwise
     */
    protected boolean isEncapsulateSignerData() {
        return !SignaturePackaging.DETACHED.equals(signatureParameters.getSignaturePackaging());
    }

}
