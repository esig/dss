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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * This class is used to build an instance of {@code org.bouncycastle.cms.SignerInfoGenerator}
 *
 */
public class CMSSignerInfoGeneratorBuilder {

    /** Defines whether the unsigned attributes should be included to a generated SignerInfoGenerator */
    private boolean includeUnsignedAttributes;

    /**
     * Default constructor
     */
    public CMSSignerInfoGeneratorBuilder() {
        // empty
    }

    /**
     * Sets whether the unsigned attributes should be included into the generated SignerInfoGenerator
     *
     * @param includeUnsignedAttributes whether the unsigned attributes should be included
     * @return this
     */
    public CMSSignerInfoGeneratorBuilder setIncludeUnsignedAttributes(boolean includeUnsignedAttributes) {
        this.includeUnsignedAttributes = includeUnsignedAttributes;
        return this;
    }

    /**
     * Builds a {@code SignerInfoGenerator} with no original document provided
     *
     * @param parameters {@link CAdESSignatureParameters}
     * @param contentSigner {@link ContentSigner}
     * @return {@link SignerInfoGenerator}
     */
    public SignerInfoGenerator build(CAdESSignatureParameters parameters, ContentSigner contentSigner) {
        return build(null, parameters, contentSigner);
    }

    /**
     * Builds a {@code SignerInfoGenerator} for signing a {@code toSignDocument}
     *
     * @param toSignDocument {@link DSSDocument} to be signed
     * @param parameters {@link CAdESSignatureParameters}
     * @param contentSigner {@link ContentSigner}
     * @return {@link SignerInfoGenerator}
     */
    public SignerInfoGenerator build(DSSDocument toSignDocument, CAdESSignatureParameters parameters, ContentSigner contentSigner) {
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = getSignerInfoGeneratorBuilder(parameters, toSignDocument);
        return getSignerInfoGenerator(signerInfoGeneratorBuilder, contentSigner, parameters);
    }

    /**
     * This method creates a builder of SignerInfoGenerator
     *
     * @param parameters
     *            the parameters of the signature containing values for the attributes
     * @param contentToSign
     *            {@link DSSDocument} represents a content to be signed
     * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the
     *         CAdESLevelBaselineB
     */
    protected SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(
            CAdESSignatureParameters parameters, DSSDocument contentToSign) {
        final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(
                contentToSign, parameters.getReferenceDigestAlgorithm());

        final CAdESLevelBaselineB cadesProfile = new CAdESLevelBaselineB(contentToSign);
        final AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

        AttributeTable unsignedAttributes = null;
        if (includeUnsignedAttributes) {
            unsignedAttributes = cadesProfile.getUnsignedAttributes();
        }
        return getSignerInfoGeneratorBuilder(dcp, signedAttributes, unsignedAttributes);
    }

    /**
     * This method creates a builder of SignerInfoGenerator
     *
     * @param digestCalculatorProvider
     *            the digest calculator (can be pre-computed)
     * @param signedAttributes
     *            the signedAttributes
     * @param unsignedAttributes
     *            the unsignedAttributes
     * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
     */
    protected SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(
            DigestCalculatorProvider digestCalculatorProvider, AttributeTable signedAttributes, AttributeTable unsignedAttributes) {

        if (CMSUtils.isEmpty(signedAttributes)) {
            signedAttributes = null;
        }
        final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
        if (CMSUtils.isEmpty(unsignedAttributes)) {
            unsignedAttributes = null;
        }
        final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

        SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
        sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
        sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
        return sigInfoGeneratorBuilder;
    }

    /**
     * @param signerInfoGeneratorBuilder
     *            the SignerInfoGeneratorBuilder
     * @param contentSigner
     *            the content signer
     * @return SignerInfoGenerator generated by the given builder according to the parameters
     */
    private SignerInfoGenerator getSignerInfoGenerator(SignerInfoGeneratorBuilder signerInfoGeneratorBuilder,
                                                       ContentSigner contentSigner,
                                                       CAdESSignatureParameters parameters) {
        try {
            if (parameters.getSigningCertificate() == null) {
                if (parameters.isGenerateTBSWithoutCertificate()) {
                    // Generate data-to-be-signed without signing certificate
                    final SignerId signerId = new SignerId(DSSUtils.EMPTY_BYTE_ARRAY);
                    return signerInfoGeneratorBuilder.build(contentSigner, signerId.getSubjectKeyIdentifier());

                } else {
                    throw new IllegalArgumentException("Signing-certificate is not provided! " +
                            "Use #setGenerateWithoutCertificates(true) method.");
                }
            }

            final X509CertificateHolder certHolder = DSSASN1Utils.getX509CertificateHolder(parameters.getSigningCertificate());
            return signerInfoGeneratorBuilder.build(contentSigner, certHolder);

        } catch (OperatorCreationException e) {
            throw new DSSException(String.format("Unable to create a SignerInfoGenerator. Reason : %s", e.getMessage()), e);
        }
    }

}
