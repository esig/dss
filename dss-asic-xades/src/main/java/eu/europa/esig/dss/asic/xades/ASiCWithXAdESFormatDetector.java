package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ASiCFormatDetector;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.List;

/**
 * This class verifies whether the provided document is a supported container by the dss-asic-xades implementation
 *
 */
public class ASiCWithXAdESFormatDetector implements ASiCFormatDetector {

    /**
     * Default constructor
     */
    public ASiCWithXAdESFormatDetector() {
        // empty
    }

    @Override
    public boolean isSupportedZip(DSSDocument document) {
        if (ASiCUtils.isZip(document)) {
            List<String> filenames = ZipUtils.getInstance().extractEntryNames(document);
            if (ASiCUtils.isASiCWithXAdES(filenames)) {
                return true;
            }
            return !ASiCUtils.isASiCWithCAdES(filenames);
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
            if (ASiCUtils.isASiCWithXAdES(filenames)) {
                return true;
            }
            return !ASiCUtils.isASiCWithCAdES(filenames);
        }
        return false;
    }

    @Override
    public boolean isSupportedZip(ASiCContent asicContent) {
        List<String> entryNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        return !ASiCUtils.isASiCWithCAdES(entryNames);
    }

    @Override
    public boolean isSupportedASiC(ASiCContent asicContent) {
        List<String> entryNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        return ASiCUtils.filesContainMetaInfFolder(entryNames) && !ASiCUtils.isASiCWithCAdES(entryNames);
    }

}
