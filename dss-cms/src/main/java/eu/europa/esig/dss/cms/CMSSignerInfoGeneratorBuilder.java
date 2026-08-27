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
package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.cms.operator.CustomMessageDigestCalculatorProvider;
import eu.europa.esig.dss.cms.operator.PrecomputedDigestCalculatorProvider;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 * This class is used to build an instance of {@code org.bouncycastle.cms.SignerInfoGenerator}
 *
 */
public class CMSSignerInfoGeneratorBuilder {

    /** The signing-certificate of the signer */
    protected CertificateToken signingCertificate;

    /** Digest algorithm to be used on message-digest computation */
    protected DigestAlgorithm digestAlgorithm;

    /** Attributes to be signed */
    protected AttributeTable signedAttributes;

    /** Unsigned attributes */
    protected AttributeTable unsignedAttributes;

    /**
     * Default constructor
     */
    public CMSSignerInfoGeneratorBuilder() {
        // empty
    }

    /**
     * Sets the signing-certificate of the signer
     *
     * @param signingCertificate {@link CertificateToken}
     * @return this {@link CMSSignerInfoGeneratorBuilder}
     */
    public CMSSignerInfoGeneratorBuilder setSigningCertificate(CertificateToken signingCertificate) {
        this.signingCertificate = signingCertificate;
        return this;
    }

    /**
     * Sets the Digest Algorithm to be used on message-digest computation
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @return this {@link CMSSignerInfoGeneratorBuilder}
     */
    public CMSSignerInfoGeneratorBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    /**
     * Sets the signed attributes
     *
     * @param signedAttributes {@link AttributeTable}
     * @return this {@link CMSSignerInfoGeneratorBuilder}
     */
    public CMSSignerInfoGeneratorBuilder setSignedAttributes(AttributeTable signedAttributes) {
        this.signedAttributes = signedAttributes;
        return this;
    }

    /**
     * Sets the unsigned attributes
     *
     * @param unsignedAttributes {@link AttributeTable}
     * @return this {@link CMSSignerInfoGeneratorBuilder}
     */
    public CMSSignerInfoGeneratorBuilder setUnsignedAttributes(AttributeTable unsignedAttributes) {
        this.unsignedAttributes = unsignedAttributes;
        return this;
    }

    /**
     * Builds a {@code SignerInfoGenerator} with no original document provided
     *
     * @param contentSigner {@link ContentSigner}
     * @return {@link SignerInfoGenerator}
     */
    public SignerInfoGenerator build(ContentSigner contentSigner) {
        // TODO : deprecate ?
        return build(null, contentSigner);
    }

    /**
     * Builds a {@code SignerInfoGenerator} for signing a {@code toSignDocument}
     *
     * @param toSignDocument {@link DSSDocument} to be signed
     * @param contentSigner {@link ContentSigner}
     * @return {@link SignerInfoGenerator}
     */
    public SignerInfoGenerator build(DSSDocument toSignDocument, ContentSigner contentSigner) {
        DigestCalculatorProvider digestCalculatorProvider = getDigestCalculatorProvider(toSignDocument);
        SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = getSignerInfoGeneratorBuilder(digestCalculatorProvider);
        return getSignerInfoGenerator(signerInfoGeneratorBuilder, contentSigner);
    }

    /**
     * Returns a {@code DigestCalculatorProvider}
     *
     * @param toSignDocument {@link DSSDocument} to sign
     * @return {@link DigestCalculatorProvider}
     */
    protected DigestCalculatorProvider getDigestCalculatorProvider(DSSDocument toSignDocument) {
        if (toSignDocument != null && digestAlgorithm != null) {
            return new CustomMessageDigestCalculatorProvider(digestAlgorithm, toSignDocument.getDigestValue(digestAlgorithm));
        } else if (toSignDocument instanceof DigestDocument) {
            return new PrecomputedDigestCalculatorProvider(toSignDocument);
        }
        return new BcDigestCalculatorProvider();
    }

    /**
     * This method creates a builder of SignerInfoGenerator
     *
     * @param digestCalculatorProvider
     *            the digest calculator (can be pre-computed)
     * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
     */
    protected SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(DigestCalculatorProvider digestCalculatorProvider) {
        if (DSSASN1Utils.isEmpty(signedAttributes)) {
            signedAttributes = null;
        }
        final CMSSignedAttributeTableGenerator signedAttributeGenerator = new CMSSignedAttributeTableGenerator(signedAttributes);

        // Unsigned attributes can't be an empty set (RFC 5652 5.3.)
        if (DSSASN1Utils.isEmpty(unsignedAttributes)) {
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
                                                       ContentSigner contentSigner) {
        try {
            if (signingCertificate != null) {
                final X509CertificateHolder certHolder = DSSASN1Utils.getX509CertificateHolder(signingCertificate);
                return signerInfoGeneratorBuilder.build(contentSigner, certHolder);

            } else {
                // Generate data-to-be-signed without signing certificate
                final SignerId signerId = new SignerId(DSSUtils.EMPTY_BYTE_ARRAY);
                return signerInfoGeneratorBuilder.build(contentSigner, signerId.getSubjectKeyIdentifier());
            }

        } catch (OperatorCreationException e) {
            throw new DSSException(String.format("Unable to create a SignerInfoGenerator. Reason : %s", e.getMessage()), e);
        }
    }

}
