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
package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineT;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cades.signature.CustomContentSigner;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.signature.SignatureValueChecker;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CMSSignedDataBuilder;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;

import java.util.Collections;
import java.util.Objects;

/**
 * This service is used to generate a CMSSignedData used for incorporation
 * within a PDF document for a PAdES signature creation.
 * <p>
 * To create a CMS with the current class, please follow the algorithm:
 * 1) Compute DTBS using message-digest of the PDF signature's ByteRange:
 *    {@code ToBeSigned toBeSigned = getDataToSign(Digest messageDigest, PAdESSignatureParameters parameters)};
 * 2) Create signature value using private-key signing:
 *    {@code SignatureValue signatureValue = *sign toBeSigned data*};
 * 3) Create CMS signature signing the message-digest:
 *    {@code CMSSignedDocument cmsSignature = signMessageDigest(
 *            Digest messageDigest, PAdESSignatureParameters parameters, SignatureValue signatureValue)};
 * <p>
 * NOTE : This class does not create CAdES-BASELINE signatures, but CAdES-Extended signatures as per ETSI EN 319 122-2,
 *        suitable for a PAdES-BASELINE creation.
 *
 */
public class ExternalCMSService {

    /**
     * The CertificateVerifier to use for a certificate chain validation
     */
    private final CertificateVerifier certificateVerifier;

    /** The TSPSource to use for timestamp requests */
    private TSPSource tspSource;

    /**
     * This is the default constructor for {@code PAdESCMSGeneratorService}.
     *
     * @param certificateVerifier
     *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
     *            in the context of a signature.
     */
    public ExternalCMSService(final CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * This setter allows to define the TSP (timestamp provider) source for T-level signature creation.
     *
     * @param tspSource
     *            The time stamp source which is used when timestamping the signature.
     */
    public void setTspSource(final TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * This method is used to compute signed-attributes of a CMSSignedData to be used for a private-key signing.
     *
     * @param messageDigest {@link DSSMessageDigest}
     *                            representing message-digest of a ByteRange content prepared
     *                            for a PDF signature creation
     * @param parameters {@link PAdESSignatureParameters}
     *                            containing configuration for CMS creation
     * @return {@link ToBeSigned} representing the data to be cryptographically signed (used to compute SignatureValue)
     */
    public ToBeSigned getDataToSign(DSSMessageDigest messageDigest, PAdESSignatureParameters parameters) {
        Objects.requireNonNull(messageDigest, "messageDigest cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        assertConfigurationValid(messageDigest, parameters);

        return buildToBeSignedData(messageDigest, parameters);
    }

    /**
     * This method builds a {@code CMSSignedData} without executing additional checks on provided configuration
     *
     * @param messageDigest {@link DSSMessageDigest}
     *                            representing message-digest of a ByteRange content prepared
     *                            for a PDF signature creation
     * @param parameters {@link PAdESSignatureParameters}
     * @return {@link CMSSignedData}
     */
    protected ToBeSigned buildToBeSignedData(DSSMessageDigest messageDigest, PAdESSignatureParameters parameters) {
        final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
        final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

        final SignerInfoGenerator signerInfoGenerator = new PAdESSignerInfoGeneratorBuilder(messageDigest)
                .build(parameters, customContentSigner);

        final CMSSignedDataBuilder cmsSignedDataBuilder = getCMSSignedDataBuilder(parameters);
        cmsSignedDataBuilder.createCMSSignedData(signerInfoGenerator, new InMemoryDocument(messageDigest.getValue()));

        final byte[] dataToSign = customContentSigner.getOutputStream().toByteArray();
        return new ToBeSigned(dataToSign);
    }

    /**
     * This method is used to create a signed CMSSignedData to be used for incorporation within a PDF document
     * for a PAdES signature creation
     *
     * @param messageDigest {@link DSSMessageDigest}
     *                            representing digest of a ByteRange content prepared for a PDF signature creation
     * @param parameters {@link PAdESSignatureParameters}
     *                            containing configuration for CMS creation
     * @param signatureValue {@link SignatureValue}
     *                            representing private-key signing of the DTBS
     * @return {@link CMSSignedDocument} representing a CMS signature suitable for PAdES signature creation
     */
    public CMSSignedDocument signMessageDigest(DSSMessageDigest messageDigest, PAdESSignatureParameters parameters,
                                               SignatureValue signatureValue) {
        Objects.requireNonNull(messageDigest, "messageDigest cannot be null!");
        Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
        Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
        assertConfigurationValid(messageDigest, parameters);

        final CMSSignedData cmsSignedData = buildCMSSignedData(messageDigest, parameters, signatureValue);

        parameters.reinit();
        return new CMSSignedDocument(cmsSignedData);
    }

    /**
     * This method builds a {@code CMSSignedData} without executing additional checks on provided configuration
     *
     * @param messageDigest {@link DSSMessageDigest} representing digest of PDF ByteRange to be signed
     * @param parameters {@link PAdESSignatureParameters}
     * @param signatureValue {@link SignatureValue}
     * @return {@link CMSSignedData}
     */
    protected CMSSignedData buildCMSSignedData(DSSMessageDigest messageDigest, PAdESSignatureParameters parameters,
                                               SignatureValue signatureValue) {
        final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
        final SignatureLevel signatureLevel = parameters.getSignatureLevel();
        Objects.requireNonNull(signatureAlgorithm, "SignatureAlgorithm cannot be null!");
        Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");

        signatureValue = new SignatureValueChecker().ensureSignatureValue(signatureValue, parameters.getSignatureAlgorithm());
        final CustomContentSigner customContentSigner = new CustomContentSigner(
                signatureAlgorithm.getJCEId(), signatureValue.getValue());

        final SignerInfoGenerator signerInfoGenerator = new PAdESSignerInfoGeneratorBuilder(messageDigest)
                .build(parameters, customContentSigner);

        CMSSignedData cmsSignedData = getCMSSignedDataBuilder(parameters)
                .createCMSSignedData(signerInfoGenerator, new InMemoryDocument(messageDigest.getValue()));

        if (!SignatureLevel.PAdES_BASELINE_B.equals(signatureLevel)) {
            Objects.requireNonNull(tspSource, "TSPSource shall be provided for T-level creation!");
            DigestDocument digestDocument = DSSUtils.toDigestDocument(messageDigest);
            parameters.getContext().setDetachedContents(Collections.singletonList(digestDocument));

            CAdESLevelBaselineT cadesLevelBaselineT = new CAdESLevelBaselineT(tspSource, certificateVerifier);
            cmsSignedData = cadesLevelBaselineT.extendCMSSignatures(cmsSignedData, parameters);
        }
        return cmsSignedData;
    }

    /**
     * This method verifies whether the provided {@code parameters} are valid for the external CMS creation process
     *
     * @param messageDigest {@link DSSMessageDigest} representing message-digest computed on PDF signature byte range
     * @param parameters {@link PAdESSignatureParameters} to be checked
     */
    protected void assertConfigurationValid(DSSMessageDigest messageDigest, PAdESSignatureParameters parameters) {
        Objects.requireNonNull(parameters.getSignatureLevel(), "SignatureLevel shall be defined!");

        final SignatureLevel signatureLevel = parameters.getSignatureLevel();
        if (!SignatureLevel.PAdES_BASELINE_B.equals(signatureLevel) &&
                !SignatureLevel.PAdES_BASELINE_T.equals(signatureLevel)) {
            throw new IllegalArgumentException(String.format(
                    "SignatureLevel '%s' is not supported within PAdESCMSGeneratorService!", signatureLevel));
        }
        assertSigningCertificateValid(parameters);
        if (messageDigest.getAlgorithm() != parameters.getDigestAlgorithm()) {
            throw new IllegalArgumentException(String.format("The DigestAlgorithm provided within Digest '%s' " +
                    "does not correspond to the one defined in SignatureParameters '%s'!",
                    messageDigest.getAlgorithm(), parameters.getDigestAlgorithm()));
        }
    }

    /**
     * This method raises an exception if the signing rules forbid the use the certificate.
     *
     * @param parameters
     *            set of driving signing parameters
     */
    protected void assertSigningCertificateValid(final AbstractSignatureParameters<?> parameters) {
        final CertificateToken signingCertificate = parameters.getSigningCertificate();
        if (signingCertificate == null) {
            if (parameters.isGenerateTBSWithoutCertificate()) {
                return;
            } else {
                throw new IllegalArgumentException("Signing Certificate is not defined! " +
                        "Set signing certificate or use method setGenerateTBSWithoutCertificate(true).");
            }
        }

        final SignatureRequirementsChecker signatureRequirementsChecker = new SignatureRequirementsChecker(
                certificateVerifier, parameters);
        signatureRequirementsChecker.assertSigningCertificateIsValid(signingCertificate);
    }

    private CMSSignedDataBuilder getCMSSignedDataBuilder(PAdESSignatureParameters parameters) {
        return new CMSSignedDataBuilder()
                .setSigningCertificate(parameters.getSigningCertificate())
                .setCertificateChain(parameters.getCertificateChain())
                .setGenerateWithoutCertificates(parameters.isGenerateTBSWithoutCertificate())
                .setTrustAnchorBPPolicy(parameters.bLevel().isTrustAnchorBPPolicy())
                .setTrustedCertificateSource(certificateVerifier.getTrustedCertSources())
                .setEncapsulate(false);
    }

}
