package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESArchiveManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CMSSignedDataBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSSignedData;

import java.util.List;

/**
 * This class is used to extend an ASiC with CAdES signatures to LTA-level
 *
 */
public class ASiCWithCAdESLevelBaselineLTA extends ASiCWithCAdESSignatureExtension {

    /** The default timestamp document name */
    private static final String ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP = ASiCUtils.META_INF_FOLDER + "timestamp001.tst";

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param tspSource           {@link TSPSource}
     */
    public ASiCWithCAdESLevelBaselineLTA(CertificateVerifier certificateVerifier, TSPSource tspSource) {
        super(certificateVerifier, tspSource);
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
        List<DSSDocument> timestampDocuments = asicContent.getTimestampDocuments();
        // shall be computed on the first step, before timestamp extension/creation
        String timestampFilename = getArchiveTimestampFilename(timestampDocuments);

        ManifestFile lastManifestFile = getLastManifestFile(asicContent.getAllManifestDocuments());

        DSSDocument lastTimestamp = getLastTimestampDocument(lastManifestFile, timestampDocuments);
        if (lastTimestamp != null) {
            ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContent);
            validator.setCertificateVerifier(certificateVerifier);

            final List<AdvancedSignature> allSignatures = validator.getAllSignatures();
            final List<TimestampToken> detachedTimestamps = validator.getDetachedTimestamps();

            ValidationDataContainer validationDataContainer = validator.getValidationData(allSignatures, detachedTimestamps);
            ValidationData allValidationData = validationDataContainer.getAllValidationData();

            // ensure the validation data is not duplicated
            for (AdvancedSignature signature : allSignatures) {
                allValidationData.excludeCertificateTokens(signature.getCompleteCertificateSource().getAllCertificateTokens());
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
            lastArchiveManifest.setName(ASiCUtils.getNextASiCManifestName(ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME,
                    asicContent.getArchiveManifestDocuments()));
        }

        ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(
                asicContent, lastArchiveManifest, manifestDigestAlgorithm, timestampFilename);
        DSSDocument archiveManifest = builder.build();
        asicContent.getArchiveManifestDocuments().add(archiveManifest);

        TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(tstDigestAlgorithm, DSSUtils.digest(tstDigestAlgorithm, archiveManifest));
        DSSDocument timestamp = new InMemoryDocument(DSSASN1Utils.getDEREncoded(timeStampResponse), timestampFilename, MimeType.TST);
        asicContent.getTimestampDocuments().add(timestamp);

        return asicContent;
    }

    private String getArchiveTimestampFilename(List<DSSDocument> timestamps) {
        int num = Utils.collectionSize(timestamps) + 1;
        return ZIP_ENTRY_ASICE_METAINF_CADES_TIMESTAMP.replace("001", ASiCUtils.getPadNumber(num));
    }

    private ManifestFile getLastManifestFile(List<DSSDocument> manifests) {
        DSSDocument lastManifest = getLastArchiveManifest(manifests);
        if (lastManifest == null) {
            lastManifest = DSSUtils.getDocumentWithLastName(manifests);
        }
        if (lastManifest != null) {
            return ASiCWithCAdESManifestParser.getManifestFile(lastManifest);
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
        CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
        CMSSignedData extendedCMSSignedData = cmsSignedDataBuilder.extendCMSSignedData(cmsSignedData, validationDataForInclusion);
        return new InMemoryDocument(DSSASN1Utils.getEncoded(extendedCMSSignedData), archiveTimestamp.getName(), MimeType.TST);
    }


    private CAdESSignatureParameters getEmptyLTLevelSignatureParameters() {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
        return parameters;
    }

}
