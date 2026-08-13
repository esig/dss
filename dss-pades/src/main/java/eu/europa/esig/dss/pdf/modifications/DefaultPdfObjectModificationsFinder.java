/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.pdf.PdfSimpleObject;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Default implementation used to find the differences between two provided PDF revisions.
 *
 */
public class DefaultPdfObjectModificationsFinder implements PdfObjectModificationsFinder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultPdfObjectModificationsFinder.class);

    /** Defines the maximum value of enveloped objects tree deepness to be checked */
    private int maximumObjectVerificationDeepness = 500;

    /** Defines whether an integer shall be promoted to a real for comparison against a real number */
    private boolean laxNumericComparison = true;

    /** Used to categorize found object modifications to different groups */
    private PdfObjectModificationsFilter pdfObjectModificationsFilter;

    /**
     * Default constructor instantiating object with default configuration
     */
    public DefaultPdfObjectModificationsFinder() {
        // empty
    }

    /**
     * Sets the maximum objects verification deepness of enveloped objects to be compared.
     * <p>
     * NOTE: In case of large PDFs, a too deep object nesting structure may lead to a StackOverflowError.
     *       This parameter is needed to prevent the Error.
     *       Please adjust the value in case you system may handle less or more recursion.
     * <p>
     * Default: 500
     *
     * @param maximumObjectVerificationDeepness defining the maximum recursion deepness on objects analysis
     */
    public void setMaximumObjectVerificationDeepness(int maximumObjectVerificationDeepness) {
        this.maximumObjectVerificationDeepness = maximumObjectVerificationDeepness;
    }

    /**
     * Sets whether an integer number shall be promoted to a real for comparison against a real number.
     * Example: when enabled, numbers 612.0 and 612 would be considered as equal.
     * If disabled, the numbers will not be considered as equivalent.
     * Default: TRUE (integer number is promoted to real for comparison against real number)
     *
     * @param laxNumericComparison whether the integer number shall be promoted to a real for comparison against a real number
     */
    public void setLaxNumericComparison(boolean laxNumericComparison) {
        this.laxNumericComparison = laxNumericComparison;
    }

    /**
     * Gets a {@code PdfObjectModificationsFilter}. If not set, creates a new instance.
     *
     * @return {@link PdfObjectModificationsFilter}
     */
    public PdfObjectModificationsFilter getPdfObjectModificationsFilter() {
        if (pdfObjectModificationsFilter == null) {
            pdfObjectModificationsFilter = new PdfObjectModificationsFilter();
        }
        return pdfObjectModificationsFilter;
    }

    /**
     * Sets the {@code PdfObjectModificationsFilter} used to categorize found differences between PDF objects.
     *
     * @param pdfObjectModificationsFilter {@link PdfObjectModificationsFilter}
     */
    public void setPdfObjectModificationsFilter(PdfObjectModificationsFilter pdfObjectModificationsFilter) {
        Objects.requireNonNull(pdfObjectModificationsFilter, "PdfObjectModificationsFilter cannot be null!");
        this.pdfObjectModificationsFilter = pdfObjectModificationsFilter;
    }

    @Override
    public PdfObjectModifications find(PdfDocumentReader originalRevisionReader, PdfDocumentReader finalRevisionReader) {
        final Set<ObjectModification> objectModifications = findObjectModifications(originalRevisionReader, finalRevisionReader);
        return getPdfObjectModificationsFilter().filter(objectModifications);
    }

    private Set<ObjectModification> findObjectModifications(final PdfDocumentReader originalRevisionReader,
                                                            final PdfDocumentReader finalRevisionReader) {
        final Set<ObjectModification> modifications = new LinkedHashSet<>(); // use LinkedHashSet in order to have a deterministic order
        final PdfDict signedCatalogDict = originalRevisionReader.getCatalogDictionary();
        final PdfDict finalCatalogDict = finalRevisionReader.getCatalogDictionary();
        compareObjectsRecursively(modifications, new HashSet<>(), new PdfObjectTree(PAdESConstants.CATALOG_NAME),
                PAdESConstants.CATALOG_NAME, signedCatalogDict.getKey(), signedCatalogDict, finalCatalogDict);
        return modifications;
    }

    /**
     * Returns found and categorized object differences between two provided {@code PdfDict} objects
     *
     * @param originalRevisionDict {@link PdfDict} representing dictionary extracted from original (e.g. signed) PDF revision
     * @param finalRevisionDict {@link PdfDict} representing dictionary extracted the final PDF document revision
     * @return {@link PdfObjectModifications} found between two given PDF dictionaries
     */
    public PdfObjectModifications find(PdfDict originalRevisionDict, PdfDict finalRevisionDict) {
        final Set<ObjectModification> objectModifications = new LinkedHashSet<>();
        compareDictsRecursively(objectModifications, new HashSet<>(), new PdfObjectTree(), originalRevisionDict, finalRevisionDict);
        return getPdfObjectModificationsFilter().filter(objectModifications);
    }

    private void compareDictsRecursively(Set<ObjectModification> modifications, Set<PdfObjectKey> processedObjects,
                                         PdfObjectTree objectTree, PdfDict signedDict, PdfDict finalDict) {
        final String[] signedRevObjNames = signedDict.list();
        List<String> signedRevKeyList = toOrderedList(signedRevObjNames);
        for (String objectName : signedRevKeyList) {
            if (isToSkip(objectName, signedDict, finalDict, objectTree)) {
                continue;
            }

            final PdfObjectTree currentObjectTree = objectTree.copy();
            PdfObjectKey objectKey = signedDict.getObjectKey(objectName);
            if (!isProcessedReference(processedObjects, currentObjectTree, objectKey)) {
                currentObjectTree.addKey(objectName);
                compareObjectsRecursively(modifications, processedObjects, currentObjectTree, objectName, objectKey,
                        signedDict.getObject(objectName), finalDict.getObject(objectName));
            }
        }

        final String[] finalRevObjNames = finalDict.list();
        for (String objectName : finalRevObjNames) {
            final PdfObjectTree currentObjectTree = objectTree.copy();
            if (!signedRevKeyList.contains(objectName)) {
                currentObjectTree.addKey(objectName);
                PdfObject finalObject = finalDict.getObject(objectName);
                if (finalObject instanceof PdfDict || finalObject instanceof PdfArray) {
                    PdfObjectKey objectKey = finalDict.getObjectKey(objectName);
                    updateObjectTree(currentObjectTree, objectKey);
                    modifications.add(ObjectModification.create(currentObjectTree, finalDict.getObject(objectName)));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Added entry with key '{}'.", currentObjectTree);
                    }
                } else {
                    modifications.add(ObjectModification.modify(currentObjectTree, null, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Added parameter with key name '{}'.", objectTree);
                    }
                }
            }
        }

        compareDictStreams(modifications, objectTree, signedDict, finalDict);
    }

    private List<String> toOrderedList(String[] objectNames) {
        // NOTE: We place /StructTreeRoot in the end of the execution, to avoid misinterpretation of the results
        List<String> objectNamesList = Arrays.asList(objectNames);
        if (objectNamesList.contains(PAdESConstants.STRUCT_TREE_ROOT_NAME)) {
            objectNamesList = new ArrayList<>(objectNamesList);
            if (objectNamesList.remove(PAdESConstants.STRUCT_TREE_ROOT_NAME)) {
                objectNamesList.add(PAdESConstants.STRUCT_TREE_ROOT_NAME);
            }
        }
        return objectNamesList;
    }

    /**
     * This method skips comparison of entries that otherwise may be reached from elsewhere,
     * thus avoiding unnecessary recursion
     *
     * @param objectName {@link String} name of the object to compare
     * @param signedDict {@link PdfDict} dictionary found in a signed revision
     * @param finalDict {@link PdfDict} dictionary found in a final revision
     * @param objectTree {@link PdfObjectTree} to the current object
     * @return TRUE if the comparison is to be skipped, FALSE otherwise
     */
    protected boolean isToSkip(String objectName, PdfDict signedDict, PdfDict finalDict, PdfObjectTree objectTree) {
        PdfObjectKey signedObjectKey = signedDict.getObjectKey(objectName);
        PdfObjectKey finalObjectKey = finalDict.getObjectKey(objectName);
        /*
         * We evaluate only indirectly referenced objects, all others shall be compared
         */
        if (signedObjectKey == null || !signedObjectKey.equals(finalObjectKey)) {
            return false;
        }

        if (PAdESConstants.PARENT_NAME.equals(objectName)) {
            /*
             * Parent dictionary is normally found elsewhere
             */
            return true;

        } else if (PAdESConstants.PAGE_NAME.equals(objectName) && PAdESConstants.TYPE_ANNOT.equals(signedDict.getNameValue(PAdESConstants.TYPE_NAME))) {
            /*
             * Indirect reference to a /P (Page) from Annot is expected to be found elsewhere
             */
            return true;

        } else if (PAdESConstants.DATA_NAME.equals(objectName) && PAdESConstants.REFERENCE_NAME.equals(objectTree.getLastKey())) {
            /*
             * /Reference /Data dictionary contains references to PDF objects covered by the signature.
             * The changes inside do not impact signature validity directly. See DSS-3813.
             */
            return true;
        }
        return false;
    }

    /**
     * Performs comparison of the {@code signedObject} and {@code finalObject} recursively processing nested entries
     *
     * @param modifications a set of found {@link ObjectModification}s
     * @param processedObjects a set of {@link PdfObjectKey} representing already processed objects
     * @param objectTree {@link PdfObjectTree} current tree
     * @param name {@link String} key of the objects to be verified
     * @param key {@link PdfObjectKey} of the object
     * @param signedObject {@link PdfObject} representing an object from the signed revision
     * @param finalObject {@link PdfObject} representing an object from the final revision
     */
    protected void compareObjectsRecursively(Set<ObjectModification> modifications, Set<PdfObjectKey> processedObjects,
                                             PdfObjectTree objectTree, String name, PdfObjectKey key, PdfObject signedObject, PdfObject finalObject) {
        if (maximumObjectVerificationDeepness < objectTree.getChainDeepness()) {
            String errorMessage = "Maximum objects verification deepness has been reached : {}. Chain of objects is skipped.";
            if (maximumObjectVerificationDeepness == 0) {
                // Skip is expected, do not return WARN message
                if (LOG.isDebugEnabled()) {
                    LOG.debug(errorMessage, maximumObjectVerificationDeepness);
                }
            } else {
                LOG.warn("Maximum objects verification deepness has been reached : {}. " +
                        "Chain of objects is skipped.", maximumObjectVerificationDeepness);
            }
            return;
        }

        updateObjectTree(objectTree, key);
        if (signedObject == null && finalObject != null) {
            if (finalObject instanceof PdfDict || finalObject instanceof PdfArray) {
                modifications.add(ObjectModification.create(objectTree, finalObject));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Added entry with key '{}'.", objectTree);
                }
            } else {
                modifications.add(ObjectModification.modify(objectTree, null, finalObject));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Added parameter with key name '{}'.", objectTree);
                }
            }

        } else if (signedObject != null && finalObject == null) {
            if (signedObject instanceof PdfDict || signedObject instanceof PdfArray) {
                modifications.add(ObjectModification.delete(objectTree, signedObject));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Deleted entry with key '{}'.", objectTree);
                }
            } else {
                modifications.add(ObjectModification.modify(objectTree, signedObject, null));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Deleted parameter with key name '{}'.", objectTree);
                }
            }

        } else if (signedObject != null && finalObject != null) {
            addProcessedReference(processedObjects, key);

            if (signedObject instanceof PdfDict && finalObject instanceof PdfDict) {
                compareDictsRecursively(modifications, processedObjects, objectTree,
                        (PdfDict) signedObject, (PdfDict) finalObject);

            } else if (signedObject instanceof PdfArray && finalObject instanceof PdfArray) {
                PdfArray signedArray = (PdfArray) signedObject;
                PdfArray finalArray = (PdfArray) finalObject;
                compareArraysRecursively(modifications, processedObjects, objectTree, name,
                        signedArray, finalArray, true);
                compareArraysRecursively(modifications, processedObjects, objectTree, name,
                        finalArray, signedArray, false);

            } else if (signedObject instanceof PdfSimpleObject && finalObject instanceof PdfSimpleObject) {
                PdfSimpleObject signedSimpleObject = (PdfSimpleObject) signedObject;
                PdfSimpleObject finalSimpleObject = (PdfSimpleObject) finalObject;
                compareSimpleObjects(modifications, objectTree, signedSimpleObject, finalSimpleObject);

            } else if (signedObject.getClass() != finalObject.getClass()) {
                modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Object with key name '{}' of type '{}' has been modified to type '{}'.",
                            objectTree, signedObject.getClass(), finalObject.getClass());
                }

            } else {
                modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                LOG.warn("Unsupported comparison of objects of type '{}' with key name '{}'",
                        signedObject.getClass(), objectTree);
            }
        }
    }

    private void compareSimpleObjects(Set<ObjectModification> modifications, PdfObjectTree objectTree,
                                      PdfSimpleObject signedObject, PdfSimpleObject finalObject) {
        Object signedObjectValue = signedObject.getValue();
        Object finalObjectValue = finalObject.getValue();
        if (signedObjectValue == null && finalObjectValue != null) {
            modifications.add(ObjectModification.modify(objectTree, null, finalObject));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Added object value with key '{}'.", objectTree);
            }

        } else if (signedObjectValue != null && finalObjectValue == null) {
            modifications.add(ObjectModification.modify(objectTree, signedObject, null));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Deleted object value with key '{}'.", objectTree);
            }

        } else if (signedObjectValue != null && finalObjectValue != null) {

            if (signedObjectValue instanceof String && finalObjectValue instanceof String) {
                if (!signedObjectValue.equals(finalObjectValue)) {
                    modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object changed with key '{}'.", objectTree);
                    }
                }

            } else if (signedObjectValue instanceof Number && finalObjectValue instanceof Number) {
                if (!signedObjectValue.equals(finalObjectValue)) {
                    if (!laxNumericComparison) {
                        modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Object changed with key '{}'.", objectTree);
                        }

                    } else if (((Number) signedObjectValue).floatValue() != ((Number) finalObjectValue).floatValue()) {
                        modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Object changed with key '{}'.", objectTree);
                        }

                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Number object with key changed type '{}'. " +
                                    "Set #setLaxNumericComparison(false) to return a warning.", objectTree);
                        }
                    }
                }

            } else if (signedObjectValue instanceof Boolean && finalObjectValue instanceof Boolean) {
                if (!signedObjectValue.equals(finalObjectValue)) {
                    modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object changed with key '{}'.", objectTree);
                    }
                }

            } else if (signedObject.getClass() != finalObject.getClass()) {
                modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Object with key name '{}' of type '{}' has been modified to type '{}'.",
                            objectTree, signedObject.getClass(), finalObject.getClass());
                }

            } else {
                modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                LOG.warn("Unsupported comparison of objects of type '{}' with key name '{}'",
                        signedObject.getClass(), objectTree);
            }
        }
    }

    private void compareArraysRecursively(Set<ObjectModification> modifications, Set<PdfObjectKey> processedObjects,
                                          PdfObjectTree objectTree, String name, PdfArray firstArray, PdfArray secondArray, boolean signedFirst) {
        for (int i = 0; i < firstArray.size(); i++) {
            final PdfObjectTree currentObjectTree = objectTree.copy();

            PdfObject signedRevObject = firstArray.getObject(i);
            PdfObject finalRevObject = null;

            PdfObjectKey objectKey = firstArray.getObjectKey(i);
            if (objectKey != null) {
                for (int j = 0; j < secondArray.size(); j++) {
                    PdfObjectKey finalObjectKey = secondArray.getObjectKey(j);
                    if (objectKey.equals(finalObjectKey)) {
                        finalRevObject = secondArray.getObject(j);
                    }
                }
            } else if (i < secondArray.size()) {
                finalRevObject = secondArray.getObject(i);
            }

            if (!isProcessedReference(processedObjects, currentObjectTree, objectKey)) {
                compareObjectsRecursively(modifications, processedObjects, currentObjectTree, name, objectKey,
                        signedFirst ? signedRevObject : finalRevObject, signedFirst ? finalRevObject : signedRevObject);
            }
        }
    }

    private boolean isProcessedReference(Set<PdfObjectKey> processedObjects, PdfObjectTree objectTree,
                                         PdfObjectKey objectKey) {
        return processedObjects.contains(objectKey) || objectTree.isProcessedReference(objectKey);
    }

    private void addProcessedReference(Set<PdfObjectKey> processedObjects, PdfObjectKey objectKey) {
        if (objectKey != null) {
            processedObjects.add(objectKey);
        }
    }

    private void updateObjectTree(PdfObjectTree objectTree,  PdfObjectKey objectKey) {
        if (objectKey != null) {
            objectTree.addReference(objectKey);
        }
    }

    private void compareDictStreams(Set<ObjectModification> modifications, PdfObjectTree objectTree,
                                           PdfDict signedDict, PdfDict finalDict) {
        final PdfObjectTree currentObjectTree = objectTree.copy();
        currentObjectTree.setStream();

        long signedStreamSize = getRawStreamSizeSecurely(signedDict);
        long finalStreamSize = getRawStreamSizeSecurely(finalDict);

        if (signedStreamSize == -1 && finalStreamSize > -1) {
            modifications.add(ObjectModification.create(currentObjectTree, finalDict));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("A stream has been added '{}'.", currentObjectTree);
                }

        } else if (signedStreamSize > -1 && finalStreamSize == -1) {
            modifications.add(ObjectModification.delete(currentObjectTree, signedDict));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("A stream has been removed '{}'.", currentObjectTree);
                }

        } else if (signedStreamSize != finalStreamSize) {
            modifications.add(ObjectModification.modify(currentObjectTree, signedDict, finalDict));
            if (LOG.isDebugEnabled()) {
                LOG.debug("A stream has been modified '{}'.", currentObjectTree);
            }

        } else if (signedStreamSize > -1 && finalStreamSize > -1) {
            try (InputStream signedStream = getRawInputStreamSecurely(signedDict);
                 InputStream finalStream = getRawInputStreamSecurely(finalDict)) {
                if (!Utils.compareInputStreams(signedStream, finalStream)) {
                    modifications.add(ObjectModification.modify(currentObjectTree, signedDict, finalDict));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("A stream has been modified '{}'.", currentObjectTree);
                    }
                }
            } catch (IOException e) {
                LOG.warn("Unable to compare underlying stream binaries. Reason : {}", e.getMessage());
            }
        }

    }

    private long getRawStreamSizeSecurely(PdfDict pdfDict) {
        try {
            return pdfDict.getRawStreamSize();
        } catch (IOException e) {
            LOG.warn("Unable to read the underlying stream binaries. Reason : {}", e.getMessage());
            return -1;
        }
    }

    private InputStream getRawInputStreamSecurely(PdfDict pdfDict) throws IOException {
        InputStream stream = pdfDict.createRawInputStream();
        if (stream != null) {
            return stream;
        }
        return new ByteArrayInputStream(DSSUtils.EMPTY_BYTE_ARRAY);
    }

}
