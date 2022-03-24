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
import java.util.stream.Collectors;

/**
 * This class is used to load a relevant {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * in order merge content of two given containers.
 *
 */
public abstract class DefaultContainerMerger implements ASiCContainerMerger {

    /** An array of ASiC contents representing containers to be merged */
    protected ASiCContent[] asicContents;

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
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    protected DefaultContainerMerger(DSSDocument... containers) {
        assertNotNull(containers);
        this.asicContents = toASiCContentArray(containers);
    }

    /**
     * This constructor is used to create an {@code ASiCContainerMerger} from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    protected DefaultContainerMerger(ASiCContent... asicContents) {
        assertNotNull(asicContents);
        this.asicContents = asicContents;
    }

    private ASiCContent[] toASiCContentArray(DSSDocument... containers) {
        ASiCContent[] asicContents = new ASiCContent[containers.length];
        for (int i = 0; i < containers.length; i++) {
            asicContents[i] = getContainerExtractor(containers[i]).extract();
        }
        return asicContents;
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
    public boolean isSupported(DSSDocument... containers) {
        assertNotNull(containers);
        for (DSSDocument containerDocument : containers) {
            if (!ASiCUtils.isZip(containerDocument)) {
                throw new IllegalInputException(String.format("The document with name '%s' is not a ZIP archive!",
                        containerDocument.getName()));
            }
            if (!isSupported(containerDocument)) {
                return false;
            }
        }
        return true;
    }

    /**
     * This method verifies whether the provided {@code container} is supported by the current class
     *
     * @param container {@link DSSDocument} to verify
     * @return TRUE if the container is supported, FALSE otherwise
     */
    protected abstract boolean isSupported(DSSDocument container);

    @Override
    public boolean isSupported(ASiCContent... asicContents) {
        assertNotNull(asicContents);
        for (ASiCContent asicContent : asicContents) {
            if (!isSupported(asicContent)) {
                return false;
            }
        }
        return true;
    }

    /**
     * This method verifies whether the provided {@code ASiCContent} is supported by the current class
     *
     * @param asicContent {@link ASiCContent} to verify
     * @return TRUE if the ASIC Content is supported, FALSE otherwise
     */
    protected abstract boolean isSupported(ASiCContent asicContent);

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
        if (asicContents == null || asicContents.length == 0) {
            throw new NullPointerException("At least one container shall be provided!");
        }

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

        asicContent.setContainerType(getContainerType());
        asicContent.setZipComment(getZipComment());
        asicContent.setMimeTypeDocument(getMimeTypeDocument());

        asicContent.setSignedDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getSignedDocuments).collect(Collectors.toList())));
        asicContent.setSignatureDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getSignatureDocuments).collect(Collectors.toList())));
        asicContent.setManifestDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getManifestDocuments).collect(Collectors.toList())));
        asicContent.setArchiveManifestDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getArchiveManifestDocuments).collect(Collectors.toList())));
        asicContent.setTimestampDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getTimestampDocuments).collect(Collectors.toList())));
        asicContent.setUnsupportedDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getUnsupportedDocuments).collect(Collectors.toList())));
        asicContent.setFolders(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getFolders).collect(Collectors.toList())));

        return asicContent;
    }

    private ASiCContainerType getContainerType() {
        for (ASiCContent asicContent : asicContents) {
            if (asicContent.getContainerType() != null) {
                return asicContent.getContainerType();
            }
        }
        return null;
    }

    private String getZipComment() {
        for (ASiCContent asicContent : asicContents) {
            if (asicContent.getZipComment() != null) {
                return asicContent.getZipComment();
            }
        }
        return null;
    }

    private DSSDocument getMimeTypeDocument() {
        for (ASiCContent asicContent : asicContents) {
            if (asicContent.getMimeTypeDocument() != null) {
                return asicContent.getMimeTypeDocument();
            }
        }
        return null;
    }

    private List<DSSDocument> mergeDocumentLists(Collection<List<DSSDocument>> documentsLists) {
        List<DSSDocument> result = new ArrayList<>();
        List<String> addedDocumentNames = new ArrayList<>();
        for (List<DSSDocument> documentsList : documentsLists) {
            for (DSSDocument document : documentsList) {
                if (!addedDocumentNames.contains(document.getName())) {
                    result.add(document);
                    addedDocumentNames.add(document.getName());

                } else {
                    DSSDocument originalListDocument = DSSUtils.getDocumentWithName(result, document.getName());
                    if (!Arrays.equals(DSSUtils.toByteArray(originalListDocument), DSSUtils.toByteArray(document))) {
                        throw new UnsupportedOperationException(String.format("Unable to merge containers. " +
                                "Containers contain different documents under the same name : %s!", document.getName()));
                    }
                    // continue, no document to be added
                }
            }
        }
        return result;
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
        for (ASiCContent asicContent : asicContents) {
            if (asicContent.getAsicContainer() != null && asicContent.getAsicContainer().getName() != null) {
                return asicContent.getAsicContainer().getName();
            }
        }
        return "container";
    }

    private String getFinalExtension(ASiCContainerType asicContainerType, String originalExtension) {
        if (Utils.isStringNotEmpty(originalExtension)) {
            return originalExtension;
        } else if (asicContainerType != null) {
            MimeType mimeType = ASiCContainerType.ASiC_S.equals(asicContainerType) ? MimeType.ASICS : MimeType.ASICE;
            return MimeType.getExtension(mimeType);
        } else {
            return "zip";
        }
    }

    private void assertNotNull(DSSDocument... containers) {
        Objects.requireNonNull(containers, "Documents shall be provided!");
        if (containers.length == 0) {
            throw new NullPointerException("At least one document shall be provided!");
        }
        for (DSSDocument containerDocument : containers) {
            Objects.requireNonNull(containerDocument, "DSSDocument cannot be null!");
        }
    }

    private void assertNotNull(ASiCContent... asicContents) {
        Objects.requireNonNull(asicContents, "ASiCContents shall be provided!");
        if (asicContents.length == 0) {
            throw new NullPointerException("At least one ASiCContent shall be provided!");
        }
        for (ASiCContent asicContent : asicContents) {
            Objects.requireNonNull(asicContent, "ASiCContent cannot be null!");
        }
    }

}
