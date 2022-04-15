package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCFilenameFactory;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

/**
 * This class provides a default implementation of {@code ASiCWithXAdESFilenameFactory}
 * used within basic configuration of DSS for creation of filenames for new container entries.
 *
 */
public class DefaultASiCWithXAdESFilenameFactory extends AbstractASiCFilenameFactory implements ASiCWithXAdESFilenameFactory {

    @Override
    public String getSignatureFilename() {
        assertASiCContentIsValid();
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            return ASiCUtils.SIGNATURES_XML; // "META-INF/signatures.xml"

        } else if (ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument())) {
            return ASiCUtils.OPEN_DOCUMENT_SIGNATURES; // "META-INF/documentsignatures.xml"

        } else { // ASiC-E
            List<String> existingSignatureNames = DSSUtils.getDocumentNames(asicContent.getSignatureDocuments());
            return ASiCUtils.ASICE_METAINF_XADES_SIGNATURE.replace("001",
                    getDocumentNameSuffixRecursively(existingSignatureNames)); // "META-INF/signatures*.xml"
        }
    }

    @Override
    public String getManifestFilename() {
        return ASiCUtils.ASICE_METAINF_MANIFEST; // "META-INF/manifest.xml"
    }

    @Override
    public String getDataPackageFilename() {
        return ASiCUtils.PACKAGE_ZIP; // "package.zip"
    }

}
