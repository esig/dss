/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
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
 * in order merge content of given containers.
 *
 */
public abstract class DefaultContainerMerger implements ASiCContainerMerger {

    /** Digest algo used for internal documents comparison */
    protected static final DigestAlgorithm DEFAULT_DIGEST_ALGORITHM = DigestAlgorithm.SHA256;

    /** An array of ASiC contents representing containers to be merged */
    protected ASiCContent[] asicContents;

    /** Defines creation time of the merged container */
    private Date creationTime;

    /**
     * Empty constructor
     */
    protected DefaultContainerMerger() {
        // empty
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
        ASiCContent[] asicContentArray = new ASiCContent[containers.length];
        for (int i = 0; i < containers.length; i++) {
            asicContentArray[i] = getContainerExtractor(containers[i]).extract();
        }
        return asicContentArray;
    }

    /**
     * This method returns a relevant ASiC container extractor
     *
     * @param container {@link DSSDocument} representing a container to be extracted
     * @return {@link DefaultASiCContainerExtractor}
     */
    protected abstract DefaultASiCContainerExtractor getContainerExtractor(DSSDocument container);

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
     * This method loads a relevant {@code ASiCContainerMerger} to be used to merge given container documents
     *
     * @param containers {@link DSSDocument} to be merged
     * @return {@link ASiCContainerMerger}
     */
    public static ASiCContainerMerger fromDocuments(DSSDocument... containers) {
        assertNotNull(containers);
        ServiceLoader<ASiCContainerMergerFactory> serviceLoaders = ServiceLoader.load(ASiCContainerMergerFactory.class);
        for (ASiCContainerMergerFactory mergerFactory : serviceLoaders) {
            if (mergerFactory.isSupported(containers)) {
                return mergerFactory.create(containers);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    /**
     * This method loads a relevant {@code ASiCContainerMerger} to be used to merge given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     * @return {@link ASiCContainerMerger}
     */
    public static ASiCContainerMerger fromASiCContents(ASiCContent... asicContents) {
        assertNotNull(asicContents);
        ServiceLoader<ASiCContainerMergerFactory> serviceLoaders = ServiceLoader.load(ASiCContainerMergerFactory.class);
        for (ASiCContainerMergerFactory mergerFactory : serviceLoaders) {
            if (mergerFactory.isSupported(asicContents)) {
                return mergerFactory.create(asicContents);
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
        containerDocument.setMimeType(ASiCContainerType.ASiC_S.equals(mergeResult.getContainerType()) ? MimeTypeEnum.ASICS : MimeTypeEnum.ASICE);
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
     * Verifies whether containers can be merged
     */
    protected abstract void ensureContainerContentAllowMerge();

    /**
     * This method is used to ensure that the entry names between the containers' entries are different
     */
    protected abstract void ensureSignaturesAllowMerge();

    /**
     * This method creates a new {@code ASiCContent} by merging the given containers
     *
     * @return {@link ASiCContent}
     */
    protected ASiCContent createMergedResult() {
        ASiCContent asicContent = createEmptyContainer();

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
        asicContent.setEvidenceRecordManifestDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getEvidenceRecordManifestDocuments).collect(Collectors.toList())));
        asicContent.setTimestampDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getTimestampDocuments).collect(Collectors.toList())));
        asicContent.setEvidenceRecordDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getEvidenceRecordDocuments).collect(Collectors.toList())));
        asicContent.setUnsupportedDocuments(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getUnsupportedDocuments).collect(Collectors.toList())));
        asicContent.setFolders(mergeDocumentLists(
                Arrays.stream(asicContents).map(ASiCContent::getFolders).collect(Collectors.toList())));

        return asicContent;
    }

    /**
     * This method creates an empty container
     *
     * @return {@link ASiCContent}
     */
    protected ASiCContent createEmptyContainer() {
        ASiCContent asicContent = new ASiCContent();
        asicContent.setContainerType(getContainerType());
        return asicContent;
    }

    private ASiCContainerType getContainerType() {
        for (ASiCContent asicContent : asicContents) {
            if (asicContent.getContainerType() != null) {
                return asicContent.getContainerType();
            }
        }
        return getTargetASiCContainerType();
    }

    /**
     * This method returns a target ASiC Container Type of the current merger class
     *
     * @return {@link ASiCContainerType}
     */
    protected abstract ASiCContainerType getTargetASiCContainerType();

    private String getZipComment() {
        String zipComment = null;
        for (ASiCContent asicContent : asicContents) {
            String currentZipComment = asicContent.getZipComment();
            if (Utils.isStringNotEmpty(currentZipComment)) {
                if (Utils.isStringEmpty(zipComment)) {
                    zipComment = currentZipComment;
                } else if (zipComment != null && !zipComment.equals(currentZipComment)) {
                    throw new UnsupportedOperationException(String.format("Unable to merge containers. " +
                            "Containers contain different zip comments : '%s' and '%s'!", zipComment, currentZipComment));
                }
            }
        }
        return zipComment;
    }

    private DSSDocument getMimeTypeDocument() {
        DSSDocument mimeType = null;
        for (ASiCContent asicContent : asicContents) {
            DSSDocument currentMimeTypeDocument = asicContent.getMimeTypeDocument();
            if (currentMimeTypeDocument != null) {
                if (mimeType == null) {
                    mimeType = currentMimeTypeDocument;
                } else if (!Arrays.equals(mimeType.getDigestValue(DEFAULT_DIGEST_ALGORITHM), currentMimeTypeDocument.getDigestValue(DEFAULT_DIGEST_ALGORITHM))) {
                    throw new UnsupportedOperationException(String.format("Unable to merge containers. " +
                            "Containers contain different mimetype documents!"));
                }
            }
        }
        return mimeType;
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
                    if (!Arrays.equals(originalListDocument.getDigestValue(DEFAULT_DIGEST_ALGORITHM), document.getDigestValue(DEFAULT_DIGEST_ALGORITHM))) {
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
            MimeType mimeType = ASiCContainerType.ASiC_S.equals(asicContainerType) ? MimeTypeEnum.ASICS : MimeTypeEnum.ASICE;
            return mimeType.getExtension();
        } else {
            return "zip";
        }
    }

    private static void assertNotNull(DSSDocument... containers) {
        Objects.requireNonNull(containers, "Documents shall be provided!");
        if (containers.length == 0) {
            throw new NullPointerException("At least one document shall be provided!");
        }
        for (DSSDocument containerDocument : containers) {
            Objects.requireNonNull(containerDocument, "DSSDocument cannot be null!");
        }
    }

    private static void assertNotNull(ASiCContent... asicContents) {
        Objects.requireNonNull(asicContents, "ASiCContents shall be provided!");
        if (asicContents.length == 0) {
            throw new NullPointerException("At least one ASiCContent shall be provided!");
        }
        for (ASiCContent asicContent : asicContents) {
            Objects.requireNonNull(asicContent, "ASiCContent cannot be null!");
        }
    }

}
