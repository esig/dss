package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class is used to load a relevant {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * in order merge content of two given containers.
 *
 */
public abstract class DefaultContainerMerger implements ASiCContainerMerger {

    /** Represents the first container's content to be merged */
    protected ASiCContent asicContentOne;

    /** Represents the second container's content to be merged */
    protected ASiCContent asicContentTwo;

    /** Defines creation time of the merged container */
    private Date creationTime;

    /**
     * Empty constructor
     */
    protected DefaultContainerMerger() {
    }

    /**
     * This constructor is used to create an {@code ASiCContainerMerger} from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    protected DefaultContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        this.asicContentOne = getContainerExtractor(containerOne).extract();
        this.asicContentTwo = getContainerExtractor(containerTwo).extract();
    }

    /**
     * This constructor is used to create an {@code ASiCContainerMerger} from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    protected DefaultContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        this.asicContentOne = asicContentOne;
        this.asicContentTwo = asicContentTwo;
    }

    /**
     * This method returns a relevant ASiC container extractor
     *
     * @param container {@link DSSDocument} representing a container to be extracted
     * @return {@link AbstractASiCContainerExtractor}
     */
    protected abstract AbstractASiCContainerExtractor getContainerExtractor(DSSDocument container);

    /**
     * Gets the merged container result's creation time
     *
     * @return {@link Date}
     */
    public Date getCreationTime() {
        if (creationTime == null) {
            creationTime = new Date();
        }
        return creationTime;
    }

    /**
     * Sets the creation time of the merged container result (optional)
     *
     * @param creationTime {@link Date}
     */
    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    /**
     * This method loads a relevant {@code ASiCContainerMerger} to be used to merge two given container documents
     *
     * @param containerOne {@link DSSDocument} to be merged
     * @param containerTwo {@link DSSDocument} to be merged
     * @return {@link ASiCContainerMerger}
     */
    public static ASiCContainerMerger fromDocuments(DSSDocument containerOne, DSSDocument containerTwo) {
        Objects.requireNonNull(containerOne, "Container document cannot be null!");
        Objects.requireNonNull(containerTwo, "Container document cannot be null!");
        ServiceLoader<ASiCContainerMergerFactory> serviceLoaders = ServiceLoader.load(ASiCContainerMergerFactory.class);
        for (ASiCContainerMergerFactory mergerFactory : serviceLoaders) {
            if (mergerFactory.isSupported(containerOne, containerTwo)) {
                return mergerFactory.create(containerOne, containerTwo);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    /**
     * This method loads a relevant {@code ASiCContainerMerger} to be used to merge two given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} to be merged
     * @param asicContentTwo {@link ASiCContent} to be merged
     * @return {@link ASiCContainerMerger}
     */
    public static ASiCContainerMerger fromASiCContents(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        Objects.requireNonNull(asicContentOne, "ASiC Content cannot be null!");
        Objects.requireNonNull(asicContentTwo, "ASiC Content cannot be null!");
        ServiceLoader<ASiCContainerMergerFactory> serviceLoaders = ServiceLoader.load(ASiCContainerMergerFactory.class);
        for (ASiCContainerMergerFactory mergerFactory : serviceLoaders) {
            if (mergerFactory.isSupported(asicContentOne, asicContentTwo)) {
                return mergerFactory.create(asicContentOne, asicContentTwo);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    @Override
    public boolean isSupported(DSSDocument containerOne, DSSDocument containerTwo) {
        Objects.requireNonNull(containerOne, "Container document cannot be null!");
        Objects.requireNonNull(containerTwo, "Container document cannot be null!");
        if (!ASiCUtils.isZip(containerOne) || !ASiCUtils.isZip(containerTwo)) {
            throw new IllegalInputException("One of the provided documents is not a ZIP archive!");
        }
        return isSupported(containerOne) && isSupported(containerTwo);
    }

    /**
     * This method verifies whether the provided {@code container} is supported by the current class
     *
     * @param container {@link DSSDocument} to verify
     * @return TRUE if the container is supported, FALSE otherwise
     */
    public abstract boolean isSupported(DSSDocument container);

    @Override
    public boolean isSupported(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        Objects.requireNonNull(asicContentOne, "ASiC content cannot be null!");
        Objects.requireNonNull(asicContentTwo, "ASiC content cannot be null!");
        return isSupported(asicContentOne) && isSupported(asicContentTwo);
    }

    /**
     * This method verifies whether the provided {@code ASiCContent} is supported by the current class
     *
     * @param asicContent {@link ASiCContent} to verify
     * @return TRUE if the ASIC Content is supported, FALSE otherwise
     */
    public abstract boolean isSupported(ASiCContent asicContent);

    @Override
    public DSSDocument merge() {
        ASiCContent mergeResult = mergeToASiCContent();
        DSSDocument containerDocument = ZipUtils.getInstance().createZipArchive(mergeResult, getCreationTime());
        containerDocument.setName(getFinalContainerName(mergeResult.getContainerType()));
        containerDocument.setMimeType(ASiCContainerType.ASiC_S.equals(mergeResult.getContainerType()) ? MimeType.ASICS : MimeType.ASICE);
        return containerDocument;
    }

    @Override
    public ASiCContent mergeToASiCContent() {
        ensureContainerContentAllowMerge();
        ensureSignaturesAllowMerge();
        return createMergedResult();
    }

    /**
     * Verifies whether two containers can be merged
     */
    protected abstract void ensureContainerContentAllowMerge();

    /**
     * This method is used to ensure that the entry names between the containers' entries are different
     */
    protected abstract void ensureSignaturesAllowMerge();

    /**
     * This method creates a new {@code ASiCContent} by merging the two given containers
     *
     * @return {@link ASiCContent}
     */
    protected ASiCContent createMergedResult() {
        ASiCContent asicContent = new ASiCContent();

        asicContent.setContainerType(asicContentOne.getContainerType() != null ?
                asicContentOne.getContainerType() : asicContentTwo.getContainerType());
        asicContent.setZipComment(asicContentOne.getZipComment() != null ?
                asicContentOne.getZipComment() : asicContentTwo.getZipComment());
        asicContent.setMimeTypeDocument(asicContentOne.getMimeTypeDocument() != null ?
                asicContentOne.getMimeTypeDocument() : asicContentTwo.getMimeTypeDocument());

        asicContent.setSignedDocuments(mergeDocumentLists(
                asicContentOne.getSignedDocuments(), asicContentTwo.getSignedDocuments()));
        asicContent.setSignatureDocuments(mergeDocumentLists(
                asicContentOne.getSignatureDocuments(), asicContentTwo.getSignatureDocuments()));
        asicContent.setManifestDocuments(mergeDocumentLists(
                asicContentOne.getManifestDocuments(), asicContentTwo.getManifestDocuments()));
        asicContent.setArchiveManifestDocuments(mergeDocumentLists(
                asicContentOne.getArchiveManifestDocuments(), asicContentTwo.getArchiveManifestDocuments()));
        asicContent.setTimestampDocuments(mergeDocumentLists(
                asicContentOne.getTimestampDocuments(), asicContentTwo.getTimestampDocuments()));
        asicContent.setUnsupportedDocuments(mergeDocumentLists(
                asicContentOne.getUnsupportedDocuments(), asicContentTwo.getUnsupportedDocuments()));
        asicContent.setFolders(mergeDocumentLists(asicContentOne.getFolders(), asicContentTwo.getFolders()));

        return asicContent;
    }

    private List<DSSDocument> mergeDocumentLists(List<DSSDocument> documentListOne, List<DSSDocument> documentListTwo) {
        List<DSSDocument> result = new ArrayList<>();
        appendDocumentsToList(result, documentListOne);
        appendDocumentsToList(result, documentListTwo);
        return result;
    }

    private void appendDocumentsToList(List<DSSDocument> documentsList, List<DSSDocument> documentsToAppend) {
        List<String> addedDocumentNames = new ArrayList<>(DSSUtils.getDocumentNames(documentsList));
        for (DSSDocument document : documentsToAppend) {
            if (!addedDocumentNames.contains(document.getName())) {
                documentsList.add(document);
                addedDocumentNames.add(document.getName());

            } else {
                DSSDocument originalListDocument = DSSUtils.getDocumentWithName(documentsList, document.getName());
                if (!Arrays.equals(DSSUtils.toByteArray(originalListDocument), DSSUtils.toByteArray(document))) {
                    throw new UnsupportedOperationException(String.format(
                            "Unable to merge two containers. Containers contain different documents under the same name : %s!", document.getName()));
                }
                // continue, no document to be added
            }
        }
    }

    /**
     * This method returns a filename for the merged container
     *
     * @param asicContainerType {@link ASiCContainerType} ASiC type of the merged container
     * @return {@link String} filename of the container
     */
    protected String getFinalContainerName(ASiCContainerType asicContainerType) {
        String originalFilename = getOriginalContainerFilename();
        String originalExtension = Utils.getFileNameExtension(originalFilename);
        if (Utils.isStringNotEmpty(originalExtension)) {
            // remove extension
            originalFilename = originalFilename.substring(0, originalFilename.length() - originalExtension.length() - 1);
        }

        StringBuilder sb = new StringBuilder(originalFilename);
        sb.append("-merged");
        sb.append(".");

        String finalExtension = getFinalExtension(asicContainerType, originalExtension);
        sb.append(finalExtension);

        return sb.toString();
    }

    private String getOriginalContainerFilename() {
        if (asicContentOne.getAsicContainer() != null && asicContentOne.getAsicContainer().getName() != null) {
            return asicContentOne.getAsicContainer().getName();
        }
        if (asicContentTwo.getAsicContainer() != null && asicContentTwo.getAsicContainer().getName() != null) {
            return asicContentTwo.getAsicContainer().getName();
        }
        return "container";
    }

    private String getFinalExtension(ASiCContainerType asicContainerType, String originalExtension) {
        if (Utils.isStringNotEmpty(originalExtension)) {
            return originalExtension;
        } else if (asicContainerType != null) {
            return ASiCContainerType.ASiC_S.equals(asicContainerType) ? "scs" : "sce";
        } else {
            return "zip";
        }
    }

    /**
     * This method verifies whether two given collection have shared objects
     *
     * @param firstList first collection to check
     * @param secondList second collection to check against
     * @return TRUE if collections intersect, FALSE otherwise
     */
    protected boolean intersect(Collection<?> firstList, Collection<?> secondList) {
        List<?> tempList = new ArrayList<>(firstList);
        tempList.retainAll(secondList);
        return Utils.isCollectionNotEmpty(tempList);
    }

}
