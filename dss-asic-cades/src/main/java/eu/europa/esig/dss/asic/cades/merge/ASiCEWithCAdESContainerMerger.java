package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class is used to merge ASiC-E with CAdES containers.
 *
 */
public class ASiCEWithCAdESContainerMerger extends AbstractASiCWithCAdESContainerMerger {

    /** Digest algo used for internal documents comparison */
    private static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;

    /**
     * Empty constructor
     */
    ASiCEWithCAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC-E With CAdES container merger from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    public ASiCEWithCAdESContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        super(containerOne, containerTwo);
    }

    /**
     * This constructor is used to create an ASiC-E With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    public ASiCEWithCAdESContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        super(asicContentOne, asicContentTwo);
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && (!ASiCUtils.isASiCSContainer(container) || doesNotContainSignatures(container));
    }

    private boolean doesNotContainSignatures(DSSDocument container) {
        List<String> entryNames = ZipUtils.getInstance().extractEntryNames(container);
        return !ASiCUtils.filesContainSignatures(entryNames);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && (!ASiCUtils.isASiCSContainer(asicContent) || doesNotContainSignatures(asicContent));
    }

    private boolean doesNotContainSignatures(ASiCContent asicContent) {
        return Utils.isCollectionEmpty(asicContent.getSignatureDocuments());
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        // no checks available
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Utils.collectionSize(asicContentOne.getSignatureDocuments()) + Utils.collectionSize(asicContentOne.getTimestampDocuments()) == 0 ||
                Utils.collectionSize(asicContentTwo.getSignatureDocuments()) + Utils.collectionSize(asicContentTwo.getTimestampDocuments()) == 0) {
            // no signatures or timestamps in at least one container. Can merge.
            return;
        }

        List<DSSDocument> allManifestDocumentsOne = asicContentOne.getAllManifestDocuments();
        List<DSSDocument> allManifestDocumentsTwo = asicContentTwo.getAllManifestDocuments();

        List<DSSDocument> signatureDocumentsOne = new ArrayList<>(asicContentOne.getSignatureDocuments());
        List<DSSDocument> signatureDocumentsTwo = new ArrayList<>(asicContentTwo.getSignatureDocuments());

        for (DSSDocument signatureDocumentOne : signatureDocumentsOne) {
            for (DSSDocument signatureDocumentTwo : signatureDocumentsTwo) {
                if (signatureDocumentOne.getName().equals(signatureDocumentTwo.getName())) {
                    DSSDocument manifestOne = ASiCWithCAdESManifestParser.getLinkedManifest(allManifestDocumentsOne, signatureDocumentOne.getName());
                    DSSDocument manifestTwo = ASiCWithCAdESManifestParser.getLinkedManifest(allManifestDocumentsTwo, signatureDocumentTwo.getName());
                    if (manifestOne == null || manifestTwo == null) {
                        throw new UnsupportedOperationException(String.format("Unable to merge two ASiC-E with CAdES containers. " +
                                "A signature with filename '%s' does not have a corresponding manifest file!", signatureDocumentOne.getName()));
                    }
                    if (manifestOne.getName().equals(manifestTwo.getName()) &&
                            manifestOne.getDigest(DEFAULT_DIGEST_ALGORITHM).equals(manifestTwo.getDigest(DEFAULT_DIGEST_ALGORITHM))) {
                        DSSDocument signaturesCms = mergeCmsSignatures(signatureDocumentOne, signatureDocumentTwo);
                        ASiCUtils.addOrReplaceDocument(asicContentOne.getSignatureDocuments(), signaturesCms);
                        ASiCUtils.addOrReplaceDocument(asicContentTwo.getSignatureDocuments(), signaturesCms);

                    } else {
                        throw new UnsupportedOperationException(String.format("Unable to merge two ASiC-E with CAdES containers. " +
                                "Signatures with filename '%s' sign different manifests!", signatureDocumentOne.getName()));
                    }
                }
            }
        }

        ensureManifestDocumentsValid(asicContentOne.getManifestDocuments(), asicContentTwo.getManifestDocuments(),
                ASiCUtils.ASIC_MANIFEST_FILENAME);
        ensureManifestDocumentsValid(asicContentOne.getArchiveManifestDocuments(), asicContentTwo.getArchiveManifestDocuments(),
                ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME);
    }

    private void ensureManifestDocumentsValid(List<DSSDocument> manifestsOne, List<DSSDocument> manifestsTwo, String manifestType) {
        Set<String> restrictedDocumentNames = new HashSet<>();
        restrictedDocumentNames.addAll(DSSUtils.getDocumentNames(manifestsOne));
        restrictedDocumentNames.addAll(DSSUtils.getDocumentNames(manifestsTwo));

        for (DSSDocument manifestOne : manifestsOne) {
            for (DSSDocument manifestTwo : manifestsTwo) {
                if (manifestOne.getName() != null && manifestOne.getName().equals(manifestTwo.getName())) {
                    if (ASiCWithCAdESUtils.isCoveredByManifest(asicContentOne.getAllManifestDocuments(), manifestOne.getName()) ||
                            ASiCWithCAdESUtils.isCoveredByManifest(asicContentTwo.getAllManifestDocuments(), manifestTwo.getName())) {
                        throw new UnsupportedOperationException("Unable to merge two ASiC-E with CAdES containers. " +
                                "A manifest with conflicting name in a container is covered by another manifest!");

                    } else {
                        String newSignatureName = ASiCUtils.getNextAvailableASiCEWithCAdESManifestName(restrictedDocumentNames, manifestType);
                        manifestTwo.setName(newSignatureName);
                        restrictedDocumentNames.add(newSignatureName);
                    }
                }
            }
        }
    }

}
