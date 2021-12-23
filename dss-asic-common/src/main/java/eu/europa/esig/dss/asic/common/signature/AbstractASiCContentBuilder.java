package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class used to build an instance of {@code ASiCContent}.
 * As input an ASiC Container can be used or documents to be signed
 *
 */
public abstract class AbstractASiCContentBuilder {

    /** The default name for a detached file if one is not defined */
    private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";

    /**
     * Builds the {@code ASiCContent} from the
     *
     * @param documents representing an ASiC Container or a list of documents to be signed
     * @param asicContainerType {@link ASiCContainerType} representing the target ASiC Container type
     * @return {@link ASiCContent}
     */
    public ASiCContent build(List<DSSDocument> documents, ASiCContainerType asicContainerType) {
        if (Utils.isCollectionNotEmpty(documents) && documents.size() == 1) {
            DSSDocument archiveDocument = documents.get(0);
            if (ASiCUtils.isZip(archiveDocument) && isAcceptableContainerFormat(archiveDocument)) {
                return fromZipArchive(archiveDocument, asicContainerType);
            }
        }
        return fromFiles(documents, asicContainerType);
    }

    /**
     * Method verifies whether the given {@code archiveDocument} has an acceptable to the format type
     *
     * @param archiveDocument {@link DSSDocument}
     * @return TRUE if the given document corresponds to the current format, FALSE otherwise
     */
    protected abstract boolean isAcceptableContainerFormat(DSSDocument archiveDocument);

    private ASiCContent fromZipArchive(DSSDocument archiveDoc, ASiCContainerType asicContainerType) {
        AbstractASiCContainerExtractor extractor = getContainerExtractor(archiveDoc);
        ASiCContent asicContent = extractor.extract();
        assertContainerTypeValid(asicContent, asicContainerType);

        return asicContent;
    }

    private ASiCContent fromFiles(List<DSSDocument> documents, ASiCContainerType asicContainerType) {
        assertDocumentNamesDefined(documents);

        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(asicContainerType);
        asicContent.setSignedDocuments(documents);

        return asicContent;
    }

    /**
     * Returns an instance of a corresponding container extractor class
     *
     * @param archiveDocument {@link DSSDocument} representing a container to be extracted
     * @return {@link AbstractASiCContainerExtractor}
     */
    protected abstract AbstractASiCContainerExtractor getContainerExtractor(DSSDocument archiveDocument);

    private void assertContainerTypeValid(ASiCContent result, ASiCContainerType asicContainerType) {
        if (ASiCUtils.filesContainSignatures(DSSUtils.getDocumentNames(result.getAllDocuments()))
                && Utils.isCollectionEmpty(result.getSignatureDocuments())) {
            throw new UnsupportedOperationException("Container type doesn't match");
        }
        if (asicContainerType != result.getContainerType()) {
            throw new IllegalInputException(String.format(
                    "The provided container of type '%s' does not correspond the expected format '%s'!",
                    result.getContainerType(), asicContainerType));
        }
    }

    /**
     * Checks if the document names are defined and adds them if needed
     *
     * @param documents a list of {@link DSSDocument}
     */
    private void assertDocumentNamesDefined(List<DSSDocument> documents) {
        List<DSSDocument> unnamedDocuments = getDocumentsWithoutNames(documents);
        if (unnamedDocuments.size() == 1) {
            DSSDocument dssDocument = unnamedDocuments.iterator().next();
            dssDocument.setName(ZIP_ENTRY_DETACHED_FILE);
        } else {
            for (int ii = 0; ii < unnamedDocuments.size(); ii++) {
                DSSDocument dssDocument = unnamedDocuments.get(ii);
                dssDocument.setName(ZIP_ENTRY_DETACHED_FILE + "-" + ii);
            }
        }
    }

    private List<DSSDocument> getDocumentsWithoutNames(List<DSSDocument> documents) {
        List<DSSDocument> result = new ArrayList<>();
        for (DSSDocument document : documents) {
            if (Utils.isStringBlank(document.getName())) {
                result.add(document);
            }
        }
        return result;
    }

}
