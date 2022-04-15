package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCFilenameFactory;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

/**
 * This class provides a default implementation of {@code ASiCWithCAdESFilenameFactory}
 * used within basic configuration of DSS for creation of filenames for new container entries.
 *
 */
public class DefaultASiCWithCAdESFilenameFactory extends AbstractASiCFilenameFactory implements ASiCWithCAdESFilenameFactory {

    @Override
    public String getSignatureFilename() {
        assertASiCContentIsValid();
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            return ASiCUtils.SIGNATURE_P7S; // "META-INF/signature.p7s";
        } else {
            List<String> existingSignatureNames = DSSUtils.getDocumentNames(asicContent.getSignatureDocuments());
            return ASiCUtils.ASICE_METAINF_CADES_SIGNATURE.replace("001",
                    getDocumentNameSuffixRecursively(existingSignatureNames)); // "META-INF/signature*.p7s"
        }
    }

    @Override
    public String getTimestampFilename() {
        assertASiCContentIsValid();
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            return ASiCUtils.TIMESTAMP_TST; // "META-INF/timestamp.tst";
        } else {
            List<String> existingTimestampNames = DSSUtils.getDocumentNames(asicContent.getTimestampDocuments());
            return ASiCUtils.ASICE_METAINF_CADES_TIMESTAMP.replace("001",
                    getDocumentNameSuffixRecursively(existingTimestampNames)); // "META-INF/timestamp*.tst"
        }
    }

    @Override
    public String getManifestFilename() {
        assertASiCContentIsValid();
        if (ASiCUtils.isASiCEContainer(asicContent)) {
            List<String> existingManifestNames = DSSUtils.getDocumentNames(asicContent.getManifestDocuments());
            return ASiCUtils.ASICE_METAINF_CADES_MANIFEST.replace("001",
                    getDocumentNameSuffixRecursively(existingManifestNames)); // "META-INF/ASiCManifest*.xml"
        } else {
            throw new UnsupportedOperationException("Manifest is not applicable for ASiC-S with CAdES container!");
        }
    }

    @Override
    public String getArchiveManifestFilename() {
        assertASiCContentIsValid();
        if (ASiCUtils.isASiCEContainer(asicContent)) {
            List<String> existingArchiveManifestNames = DSSUtils.getDocumentNames(asicContent.getArchiveManifestDocuments());
            return ASiCUtils.ASICE_METAINF_CADES_ARCHIVE_MANIFEST.replace("001",
                    getDocumentNameSuffixRecursively(existingArchiveManifestNames)); // "META-INF/ASiCArchiveManifest*.xml"
        } else {
            throw new UnsupportedOperationException("Manifest is not applicable for ASiC-S with CAdES container!");
        }
    }

    @Override
    public String getDataPackageFilename() {
        return ASiCUtils.PACKAGE_ZIP; // "package.zip"
    }

}
