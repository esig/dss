package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.signature.asice.ASiCEWithXAdESManifestBuilder;
import eu.europa.esig.dss.asic.xades.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.apache.xml.security.signature.Reference;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/**
 * This class is used to merge ASiC-E with XAdES containers.
 *
 */
public class ASiCEWithXAdESContainerMerger extends AbstractASiCWithXAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCEWithXAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC-E With XAdES container merger from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    public ASiCEWithXAdESContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        super(containerOne, containerTwo);
    }

    /**
     * This constructor is used to create an ASiC-E With XAdES from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    public ASiCEWithXAdESContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
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
        List<DSSDocument> signatureDocumentsOne = asicContentOne.getSignatureDocuments();
        List<DSSDocument> signatureDocumentsTwo = asicContentTwo.getSignatureDocuments();
        if (Utils.isCollectionEmpty(signatureDocumentsOne) && Utils.isCollectionEmpty(signatureDocumentsTwo)) {
            return; // no signatures -> can merge
        }

        List<DSSDocument> timestampDocumentsOne = asicContentOne.getTimestampDocuments();
        List<DSSDocument> timestampDocumentsTwo = asicContentTwo.getTimestampDocuments();
        if (Utils.isCollectionNotEmpty(timestampDocumentsOne) || Utils.isCollectionNotEmpty(timestampDocumentsTwo)) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-E with XAdES containers. " +
                    "One of the containers contains a detached timestamp!");
        }
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Utils.isCollectionEmpty(asicContentOne.getManifestDocuments()) &&
                Utils.isCollectionEmpty(asicContentTwo.getManifestDocuments()) &&
                (Utils.isCollectionEmpty(asicContentOne.getSignatureDocuments()) ||
                        Utils.isCollectionEmpty(asicContentTwo.getSignatureDocuments()))) {
            // no signatures in at least one container, nor manifests. Can merge.
            return;
        }

        List<DSSDocument> signatureDocumentsOne = asicContentOne.getSignatureDocuments();
        List<DSSDocument> signatureDocumentsTwo = asicContentTwo.getSignatureDocuments();

        List<String> coveredDocumentsOne = getCoveredDocumentNames(signatureDocumentsOne);
        List<String> coveredDocumentsTwo = getCoveredDocumentNames(signatureDocumentsTwo);

        if ((doCoverManifest(coveredDocumentsOne) || doCoverManifest(coveredDocumentsTwo)) &&
                !sameSignedDocuments(asicContentOne.getSignedDocuments(), asicContentTwo.getSignedDocuments())) {
            throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                    "manifest.xml is signed and the signer data does not match between containers!");
        }

        List<String> firstContainerSignatureNames = DSSUtils.getDocumentNames(signatureDocumentsOne);
        List<String> secondContainerSignatureNames = DSSUtils.getDocumentNames(signatureDocumentsTwo);

        if (isConflictBetweenSignatureDocumentNames(firstContainerSignatureNames, secondContainerSignatureNames)) {
            if (doCoverOtherSignatures(firstContainerSignatureNames, coveredDocumentsOne) ||
                    doCoverOtherSignatures(secondContainerSignatureNames, coveredDocumentsTwo)) {
                throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                        "A signature covers another signature file, while having same signature names in both containers!");
            }
            ensureDocumentNamesDiffer(firstContainerSignatureNames, signatureDocumentsTwo);
        }

        // Create a merged manifest.xml file, and provide it only within one container
        DSSDocument newManifest = createNewManifest(asicContentOne, asicContentTwo);
        asicContentOne.setManifestDocuments(Collections.singletonList(newManifest));
        asicContentTwo.setManifestDocuments(Collections.emptyList());
    }

    private List<String> getCoveredDocumentNames(List<DSSDocument> signatureDocuments) {
        List<String> result = new ArrayList<>();
        for (DSSDocument signatureDocument : signatureDocuments) {
            XMLDocumentValidator documentValidator = new XMLDocumentValidator(signatureDocument);
            for (AdvancedSignature signature : documentValidator.getSignatures()) {
                XAdESSignature xadesSignature = (XAdESSignature) signature;
                for (Reference reference : xadesSignature.getReferences()) {
                    String referenceURI = DSSXMLUtils.getReferenceURI(reference);
                    if (!DomUtils.startsFromHash(referenceURI) && !DomUtils.isXPointerQuery(referenceURI)) {
                        result.add(referenceURI);
                    }
                }
            }
        }
        return result;
    }

    private boolean doCoverManifest(List<String> documentNames) {
        return documentNames.contains(ASiCUtils.ASICE_METAINF_MANIFEST);
    }

    private boolean sameSignedDocuments(List<DSSDocument> signerDocumentsOne, List<DSSDocument> signerDocumentsTwo) {
        List<String> firstContainerSignerDocumentNames = DSSUtils.getDocumentNames(signerDocumentsOne);
        List<String> secondContainerSignerDocumentNames = DSSUtils.getDocumentNames(signerDocumentsTwo);
        return new HashSet<>(firstContainerSignerDocumentNames).equals(new HashSet<>(secondContainerSignerDocumentNames));
    }

    private boolean isConflictBetweenSignatureDocumentNames(List<String> signatureDocumentsOne,
                                                            List<String> signatureDocumentsTwo) {
        return intersect(signatureDocumentsOne, signatureDocumentsTwo);
    }

    private boolean doCoverOtherSignatures(List<String> signatureNames, List<String> coveredDocumentNames) {
        for (String signature : signatureNames) {
            if (coveredDocumentNames.contains(signature)) {
                return true;
            }
        }
        return false;
    }

    private DSSDocument createNewManifest(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        List<DSSDocument> manifestDocumentsOne = asicContentOne.getManifestDocuments();
        List<DSSDocument> manifestDocumentsTwo = asicContentTwo.getManifestDocuments();

        List<ManifestEntry> manifestEntriesOne = getManifestFileEntries(manifestDocumentsOne);
        List<ManifestEntry> manifestEntriesTwo = getManifestFileEntries(manifestDocumentsTwo);
        List<ManifestEntry> signedDocumentEntriesOne = ASiCUtils.toSimpleManifestEntries(asicContentOne.getSignedDocuments());
        List<ManifestEntry> signedDocumentEntriesTwo = ASiCUtils.toSimpleManifestEntries(asicContentTwo.getSignedDocuments());

        List<ManifestEntry> allManifestEntries = mergeManifestEntries(
                manifestEntriesOne, manifestEntriesTwo, signedDocumentEntriesOne, signedDocumentEntriesTwo);

        return createNewManifestXml(allManifestEntries);
    }

    private List<ManifestEntry> getManifestFileEntries(List<DSSDocument> manifestDocuments) {
        if (Utils.isCollectionEmpty(manifestDocuments)) {
            return Collections.emptyList();

        } else if (Utils.collectionSize(manifestDocuments) > 1) {
            throw new IllegalInputException("One of the containers contain multiple manifest files!");

        } else {
            DSSDocument manifestDocument = manifestDocuments.get(0);
            if (!ASiCUtils.ASICE_METAINF_MANIFEST.equals(manifestDocument.getName())) {
                throw new IllegalInputException(String.format("A manifest file shall have a name '%s'.",
                        ASiCUtils.ASICE_METAINF_MANIFEST));
            }

            ASiCEWithXAdESManifestParser parser = new ASiCEWithXAdESManifestParser(manifestDocument);
            ManifestFile manifest = parser.getManifest();
            return manifest.getEntries();
        }
    }

    private List<ManifestEntry> mergeManifestEntries(List<ManifestEntry>... manifestEntryLists) {
        List<ManifestEntry> result = new ArrayList<>();
        List<String> addedFileNames = new ArrayList<>();
        for (List<ManifestEntry> manifestEntries : manifestEntryLists) {
            for (ManifestEntry entry : manifestEntries) {
                if (!addedFileNames.contains(entry.getFileName())) {
                    result.add(entry);
                    addedFileNames.add(entry.getFileName());
                }
            }
        }
        return result;
    }

    private DSSDocument createNewManifestXml(List<ManifestEntry> manifestEntries) {
        return new ASiCEWithXAdESManifestBuilder().setEntries(manifestEntries)
                .setManifestFilename(ASiCUtils.ASICE_METAINF_MANIFEST).build();
    }

    private void ensureDocumentNamesDiffer(List<String> restrictedDocumentNames, List<DSSDocument> signatures) {
        for (DSSDocument signatureDocument : signatures) {
            if (restrictedDocumentNames.contains(signatureDocument.getName())) {
                String newSignatureName = ASiCUtils.getNextAvailableASiCEWithXAdESSignatureName(restrictedDocumentNames);
                signatureDocument.setName(newSignatureName);
                restrictedDocumentNames.add(newSignatureName);
            }
        }
    }

}
