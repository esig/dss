package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

/**
 * This class is used to merge ASiC-S with CAdES containers.
 *
 */
public class ASiCSWithCAdESContainerMerger extends AbstractASiCWithCAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCSWithCAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES container merger from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    public ASiCSWithCAdESContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        super(containerOne, containerTwo);
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    public ASiCSWithCAdESContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        super(asicContentOne, asicContentTwo);
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && !ASiCUtils.isASiCEContainer(container);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && !ASiCUtils.isASiCEContainer(asicContent);
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        List<DSSDocument> signatureDocumentsOne = asicContentOne.getSignatureDocuments();
        List<DSSDocument> signatureDocumentsTwo = asicContentTwo.getSignatureDocuments();
        List<DSSDocument> timestampDocumentsOne = asicContentOne.getTimestampDocuments();
        List<DSSDocument> timestampDocumentsTwo = asicContentTwo.getTimestampDocuments();

        if (Utils.isCollectionEmpty(signatureDocumentsOne) && Utils.isCollectionEmpty(signatureDocumentsTwo) &&
                Utils.isCollectionEmpty(timestampDocumentsOne) && Utils.isCollectionEmpty(timestampDocumentsTwo)) {
            return; // no signatures/timestamps -> can merge
        }

        if (Utils.collectionSize(signatureDocumentsOne) + Utils.collectionSize(timestampDocumentsOne) > 1 ||
                Utils.collectionSize(signatureDocumentsTwo) + Utils.collectionSize(timestampDocumentsTwo) > 1) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signature or timestamp documents!");
        }
        if (Utils.collectionSize(signatureDocumentsOne) + Utils.collectionSize(timestampDocumentsTwo) > 1 ||
                Utils.collectionSize(signatureDocumentsTwo) + Utils.collectionSize(timestampDocumentsOne) > 1) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                    "A container containing a timestamp file cannot be merged with other signed or timestamped container!");
        }
        assertSignatureDocumentNameValid(signatureDocumentsOne);
        assertSignatureDocumentNameValid(signatureDocumentsTwo);
        assertTimestampDocumentNameValid(timestampDocumentsOne);
        assertTimestampDocumentNameValid(timestampDocumentsTwo);

        List<DSSDocument> signedDocumentsOne = asicContentOne.getRootLevelSignedDocuments();
        List<DSSDocument> signedDocumentsTwo = asicContentTwo.getRootLevelSignedDocuments();
        if (Utils.collectionSize(signedDocumentsOne) > 1 || Utils.collectionSize(signedDocumentsTwo) > 1) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signer documents!");
        }

        if (Utils.isCollectionNotEmpty(signedDocumentsOne) && Utils.isCollectionNotEmpty(signedDocumentsTwo)) {
            DSSDocument signedDocumentOne = signedDocumentsOne.get(0);
            DSSDocument signedDocumentTwo = signedDocumentsTwo.get(0);
            if (signedDocumentOne.getName() == null || !signedDocumentOne.getName().equals(signedDocumentTwo.getName())) {
                throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                        "Signer documents have different names!");
            }
        }
    }

    private void assertSignatureDocumentNameValid(List<DSSDocument> documents) {
        if (Utils.isCollectionNotEmpty(documents)) {
            DSSDocument document = documents.get(0);
            if (!ASiCUtils.SIGNATURE_P7S.equals(document.getName()) ) {
                throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                        "The signature document in one of the containers has invalid naming!");
            }
        }
    }

    private void assertTimestampDocumentNameValid(List<DSSDocument> documents) {
        if (Utils.isCollectionNotEmpty(documents)) {
            DSSDocument document = documents.get(0);
            if (!ASiCUtils.TIMESTAMP_TST.equals(document.getName()) ) {
                throw new UnsupportedOperationException("Unable to merge two ASiC-S with CAdES containers. " +
                        "The timestamp document in one of the containers has invalid naming!");
            }
        }
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Utils.isCollectionEmpty(asicContentOne.getSignatureDocuments()) ||
                Utils.isCollectionEmpty(asicContentTwo.getSignatureDocuments())) {
            // one of the containers does not contain a signature document. Can merge.
            return;
        }

        DSSDocument signatureDocumentOne = asicContentOne.getSignatureDocuments().get(0);
        DSSDocument signatureDocumentTwo = asicContentTwo.getSignatureDocuments().get(0);

        DSSDocument signaturesCms = mergeCmsSignatures(signatureDocumentOne, signatureDocumentTwo);
        asicContentOne.setSignatureDocuments(Collections.singletonList(signaturesCms));
        asicContentTwo.setSignatureDocuments(Collections.emptyList());
    }

}
