package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ASiCFormatDetector;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

/**
 * This class verifies whether the provided document is a supported container by the dss-asic-cades implementation
 *
 */
public class ASiCWithCAdESFormatDetector implements ASiCFormatDetector {

    /**
     * Default constructor
     */
    public ASiCWithCAdESFormatDetector() {
        // empty
    }

    @Override
    public boolean isSupportedZip(DSSDocument document) {
        if (ASiCUtils.isZip(document)) {
            List<String> filenames = ZipUtils.getInstance().extractEntryNames(document);
            if (ASiCUtils.isASiCWithCAdES(filenames)) {
                return true;
            }
            // NOTE : areFilesContainMimetype check is executed in order to avoid documents reading
            return !ASiCUtils.isASiCWithXAdES(filenames) &&
                    (!ASiCUtils.areFilesContainMimetype(filenames) || !ASiCUtils.isContainerOpenDocument(document));
        }
        return false;
    }

    @Override
    public boolean isSupportedASiC(DSSDocument document) {
        if (ASiCUtils.isZip(document)) {
            List<String> filenames = ZipUtils.getInstance().extractEntryNames(document);
            if (!ASiCUtils.filesContainMetaInfFolder(filenames)) {
                return false;
            }
            if (ASiCUtils.isASiCWithCAdES(filenames)) {
                return true;
            }
            // NOTE : areFilesContainMimetype check is executed in order to avoid documents reading
            return !ASiCUtils.isASiCWithXAdES(filenames) &&
                    (!ASiCUtils.areFilesContainMimetype(filenames) || !ASiCUtils.isContainerOpenDocument(document));
        }
        return false;
    }

    @Override
    public boolean isSupportedZip(ASiCContent asicContent) {
        List<String> entryNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        return !ASiCUtils.isASiCWithXAdES(entryNames) &&
                (!ASiCUtils.areFilesContainMimetype(entryNames) || !ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument()));
    }

    @Override
    public boolean isSupportedASiC(ASiCContent asicContent) {
        List<String> entryNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        return ASiCUtils.filesContainMetaInfFolder(entryNames) && !ASiCUtils.isASiCWithXAdES(entryNames) &&
                (!ASiCUtils.areFilesContainMimetype(entryNames) || !ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument()));
    }

}
