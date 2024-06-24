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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESAnalyzer;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CMSSignedDataBuilder;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
import org.bouncycastle.cms.CMSSignedData;

import java.util.List;

/**
 * This class is used to extend an ASiC with CAdES signatures to LTA-level
 *
 */
public class ASiCWithCAdESLevelBaselineLTA extends ASiCWithCAdESSignatureExtension {

    private static final long serialVersionUID = 5337864432054920568L;

    /**
     * Defines rules for filename creation for timestamp and archive manifest file.
     */
    private final ASiCWithCAdESFilenameFactory asicFilenameFactory;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param tspSource           {@link TSPSource}
     */
    public ASiCWithCAdESLevelBaselineLTA(final CertificateVerifier certificateVerifier, final TSPSource tspSource) {
        this(certificateVerifier, tspSource, new DefaultASiCWithCAdESFilenameFactory());
    }

    /**
     * Constructor with filename factory
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param tspSource           {@link TSPSource}
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public ASiCWithCAdESLevelBaselineLTA(final CertificateVerifier certificateVerifier, final TSPSource tspSource,
                                         final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        super(certificateVerifier, tspSource);
        this.asicFilenameFactory = asicFilenameFactory;
    }

    @Override
    public ASiCContent extend(ASiCContent asicContent, CAdESSignatureParameters parameters) {
        asicContent = super.extend(asicContent, parameters); // LT-level extension, if required
        return extend(asicContent, getReferenceDigestAlgorithmOrDefault(parameters),
                parameters.getArchiveTimestampParameters().getDigestAlgorithm()); // LTA-level extension
    }

    /**
     * Extends {@code asicContent} with an ArchiveManifest timestamp
     *
     * NOTE: This method is to be used for a direct timestamping with an ArchiveManifest,
     *       without in-depth signature attributes (the signature extension is still applied).
     *       Use {@code extend(ASiCContent, CAdESSignatureParameters)} method for a proper signature(s) extension
     *
     * @param asicContent {@link ASiCContent} to extend
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for ArchiveManifest and timestamp creation
     * @return extended {@link ASiCContent}
     */
    public ASiCContent extend(ASiCContent asicContent, DigestAlgorithm digestAlgorithm) {
        // ensure the signatures are extended to LT-level, when necessary
        asicContent = super.extend(asicContent, getEmptyLTLevelSignatureParameters());
        return extend(asicContent, digestAlgorithm, digestAlgorithm);
    }

    /**
     * This method extends the ASiC Container, by adding a new Archive Manifest, time-stamp file
     * and necessary validation data
     *
     * @param asicContent {@link ASiCContent} representing the ASiC container
     * @param manifestDigestAlgorithm {@link DigestAlgorithm} to be used for Archive Manifest references incorporation
     * @param tstDigestAlgorithm {@link DigestAlgorithm} to be used for timestamp creation
     * @return {@link ASiCContent} extended
     */
    private ASiCContent extend(ASiCContent asicContent, DigestAlgorithm manifestDigestAlgorithm,
                              DigestAlgorithm tstDigestAlgorithm) {
        // shall be computed on the first step, before timestamp extension/creation
        String timestampFilename = asicFilenameFactory.getTimestampFilename(asicContent);

        ManifestFile lastManifestFile = getLastManifestFile(asicContent.getAllManifestDocuments());

        List<DSSDocument> timestampDocuments = asicContent.getTimestampDocuments();
        DSSDocument lastTimestamp = getLastTimestampDocument(lastManifestFile, timestampDocuments);
        if (lastTimestamp != null) {
            ASiCContainerWithCAdESAnalyzer validator = new ASiCContainerWithCAdESAnalyzer(asicContent);
            validator.setCertificateVerifier(certificateVerifier);
            validator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);

            final List<AdvancedSignature> allSignatures = validator.getAllSignatures();
            final List<TimestampToken> detachedTimestamps = validator.getDetachedTimestamps();

            ValidationDataContainer validationDataContainer = validator.getValidationData(allSignatures, detachedTimestamps);
            ValidationData allValidationData = validationDataContainer.getAllValidationData();

            // ensure the validation data is not duplicated
            for (AdvancedSignature signature : allSignatures) {
                allValidationData.excludeCertificateTokens(signature.getCompleteCertificateSource().getCertificates());
                allValidationData.excludeCRLTokens(signature.getCompleteCRLSource().getAllRevocationBinaries());
                allValidationData.excludeOCSPTokens(signature.getCompleteOCSPSource().getAllRevocationBinaries());
            }
            for (TimestampToken timestampToken : detachedTimestamps) {
                allValidationData.excludeCertificateTokens(timestampToken.getCertificateSource().getCertificates());
                allValidationData.excludeCRLTokens(timestampToken.getCRLSource().getAllRevocationBinaries());
                allValidationData.excludeOCSPTokens(timestampToken.getOCSPSource().getAllRevocationBinaries());
            }

            // a newer version of the timestamp must be created
            DSSDocument extendedTimestamp = extendTimestamp(lastTimestamp, allValidationData);
            ASiCUtils.addOrReplaceDocument(asicContent.getTimestampDocuments(), extendedTimestamp);
        }

        DSSDocument lastArchiveManifest = null;
        if (lastManifestFile != null && isLastArchiveManifest(lastManifestFile.getFilename())) {
            lastArchiveManifest = lastManifestFile.getDocument();
            lastArchiveManifest.setName(asicFilenameFactory.getArchiveManifestFilename(asicContent));
        }

        ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(
                asicContent, lastArchiveManifest, manifestDigestAlgorithm, timestampFilename);
        DSSDocument archiveManifest = builder.build();
        asicContent.getArchiveManifestDocuments().add(archiveManifest);

        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(tstDigestAlgorithm, DSSUtils.digest(tstDigestAlgorithm, archiveManifest));
        DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timeStampResponse), timestampFilename, MimeTypeEnum.TST);
        asicContent.getTimestampDocuments().add(timestamp);

        return asicContent;
    }

    private ManifestFile getLastManifestFile(List<DSSDocument> manifests) {
        DSSDocument lastManifest = getLastArchiveManifest(manifests);
        if (lastManifest == null) {
            lastManifest = DSSUtils.getDocumentWithLastName(manifests);
        }
        if (lastManifest != null) {
            return ASiCManifestParser.getManifestFile(lastManifest);
        }
        return null;
    }

    private DSSDocument getLastArchiveManifest(List<DSSDocument> manifests) {
        if (Utils.isCollectionNotEmpty(manifests)) {
            for (DSSDocument manifest : manifests) {
                if (isLastArchiveManifest(manifest.getName())) {
                    return manifest;
                }
            }
        }
        return null;
    }

    private boolean isLastArchiveManifest(String fileName) {
        return ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME.equals(fileName);
    }

    private DSSDocument getLastTimestampDocument(ManifestFile lastManifestFile, List<DSSDocument> timestamps) {
        if (lastManifestFile != null) {
            return DSSUtils.getDocumentWithName(timestamps, lastManifestFile.getSignatureFilename());
        }
        return DSSUtils.getDocumentWithLastName(timestamps);
    }

    private DSSDocument extendTimestamp(DSSDocument archiveTimestamp, ValidationData validationDataForInclusion) {
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(archiveTimestamp);
        CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder().setOriginalCMSSignedData(cmsSignedData);
        CMSSignedData extendedCMSSignedData = cmsSignedDataBuilder.extendCMSSignedData(
                validationDataForInclusion.getCertificateTokens(), validationDataForInclusion.getCrlTokens(),
                validationDataForInclusion.getOcspTokens());
        return new InMemoryDocument(DSSASN1Utils.getEncoded(extendedCMSSignedData), archiveTimestamp.getName(), MimeTypeEnum.TST);
    }


    private CAdESSignatureParameters getEmptyLTLevelSignatureParameters() {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
        return parameters;
    }

    @Override
    protected boolean extensionRequired(CAdESSignatureParameters parameters, boolean coveredByManifest) {
        return !coveredByManifest;
    }

    @Override
    protected void assertExtendSignaturePossible(CAdESSignatureParameters parameters, boolean coveredByManifest) {
        if (coveredByManifest) {
            throw new IllegalInputException(String.format(
                    "Cannot extend signature to '%s'. The signature is already covered by an archive manifest.", parameters.getSignatureLevel()));
        }
    }

}
