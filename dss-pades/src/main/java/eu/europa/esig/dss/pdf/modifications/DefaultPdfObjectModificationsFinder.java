package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Default implementation used to find the differences between two provided PDF revisions.
 *
 */
public class DefaultPdfObjectModificationsFinder implements PdfObjectModificationsFinder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultPdfObjectModificationsFinder.class);

    /** Defines the maximum value of enveloped objects tree deepness to be checked */
    private int maximumObjectVerificationDeepness = 500;

    /**
     * Sets the maximum objects verification deepness of enveloped objects to be compared.
     *
     * NOTE: In case of large PDFs, a too deep object nesting structure may lead to a StackOverflowError.
     *       This parameter is needed to prevent the Error.
     *       Please adjust the value in case you system may handle less or more recursion.
     *
     * Default: 500
     *
     * @param maximumObjectVerificationDeepness defining the maximum recursion deepness on objects analysis
     */
    public void setMaximumObjectVerificationDeepness(int maximumObjectVerificationDeepness) {
        this.maximumObjectVerificationDeepness = maximumObjectVerificationDeepness;
    }

    @Override
    public Set<ObjectModification> find(final PdfDocumentReader originalRevisionReader,
                                        final PdfDocumentReader finalRevisionReader) {
        final Set<ObjectModification> modifications = new LinkedHashSet<>(); // use LinkedHashSet in order to have a deterministic order
        final PdfDict signedCatalogDict = originalRevisionReader.getCatalogDictionary();
        final PdfDict finalCatalogDict = finalRevisionReader.getCatalogDictionary();
        compareObjectsRecursively(modifications, new HashSet<>(), new PdfObjectTree(PAdESConstants.CATALOG_NAME),
                PAdESConstants.CATALOG_NAME, signedCatalogDict, finalCatalogDict);
        return modifications;
    }

    private void compareDictsRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
                                                PdfObjectTree objectTree, PdfDict signedDict, PdfDict finalDict) {
        final String[] signedRevKeys = signedDict.list();
        final String[] finalRevKeys = finalDict.list();
        for (String key : signedRevKeys) {
            final PdfObjectTree currentObjectTree = objectTree.copy();
            Long objectNumber = signedDict.getObjectNumber(key);
            if (!isProcessedReference(processedObjects, currentObjectTree, key, objectNumber)) {
                currentObjectTree.addKey(key);
                addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
                compareObjectsRecursively(modifications, processedObjects, currentObjectTree, key,
                        signedDict.getObject(key), finalDict.getObject(key));
            }
        }

        List<String> signedRevKeyList = Arrays.asList(signedRevKeys);
        for (String key : finalRevKeys) {
            final PdfObjectTree currentObjectTree = objectTree.copy();
            if (!signedRevKeyList.contains(key)) {
                currentObjectTree.addKey(key);
                Object finalObject = finalDict.getObject(key);
                if (finalObject instanceof PdfDict || finalObject instanceof PdfArray) {
                    Long objectNumber = finalDict.getObjectNumber(key);
                    addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
                    modifications.add(ObjectModification.create(currentObjectTree, finalDict.getObject(key)));
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

    private void compareObjectsRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
                                                  PdfObjectTree objectTree, String key, Object signedObject, Object finalObject) {
        if (maximumObjectVerificationDeepness < objectTree.getChainDeepness()) {
            LOG.warn("Maximum objects verification deepness has been reached : {}. " +
                    "Chain of objects is skipped.", maximumObjectVerificationDeepness);
            return;
        }

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
            if (signedObject instanceof PdfDict && finalObject instanceof PdfDict) {
                compareDictsRecursively(modifications, processedObjects, objectTree,
                        (PdfDict) signedObject, (PdfDict) finalObject);

            } else if (signedObject instanceof PdfArray && finalObject instanceof PdfArray) {
                PdfArray signedArray = (PdfArray) signedObject;
                PdfArray finalArray = (PdfArray) finalObject;
                compareArraysRecursively(modifications, processedObjects, objectTree, key,
                        signedArray, finalArray, true);
                compareArraysRecursively(modifications, processedObjects, objectTree, key,
                        finalArray, signedArray, false);

            } else if (signedObject instanceof String && finalObject instanceof String) {
                if (!signedObject.equals(finalObject)) {
                    modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object changed with key '{}'.", objectTree);
                    }
                }

            } else if (signedObject instanceof Number && finalObject instanceof Number) {
                if (!signedObject.equals(finalObject)) {
                    modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object changed with key '{}'.", objectTree);
                    }
                }

            } else if (signedObject instanceof Boolean && finalObject instanceof Boolean) {
                if (!signedObject.equals(finalObject)) {
                    modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Object changed with key '{}'.", objectTree);
                    }
                }

            } else {
                modifications.add(ObjectModification.modify(objectTree, signedObject, finalObject));
                LOG.warn("Unsupported objects found with key '{}' of types '{}' and '{}'",
                        objectTree, signedObject.getClass(), finalObject.getClass());
            }
        }
    }

    private void compareArraysRecursively(Set<ObjectModification> modifications, Set<String> processedObjects,
                                                 PdfObjectTree objectTree, String key, PdfArray firstArray, PdfArray secondArray, boolean signedFirst) {
        for (int i = 0; i < firstArray.size(); i++) {
            final PdfObjectTree currentObjectTree = objectTree.copy();

            Object signedRevObject = firstArray.getObject(i);
            Object finalRevObject = null;

            Long objectNumber = firstArray.getObjectNumber(i);
            if (objectNumber != null) {
                for (int j = 0; j < secondArray.size(); j++) {
                    Long finalObjectNumber = secondArray.getObjectNumber(j);
                    if (objectNumber.equals(finalObjectNumber)) {
                        finalRevObject = secondArray.getObject(j);
                    }
                }
            } else if (i < secondArray.size()) {
                finalRevObject = secondArray.getObject(i);
            }

            if (!isProcessedReference(processedObjects, currentObjectTree, key, objectNumber)) {
                addProcessedReference(processedObjects, currentObjectTree, key, objectNumber);
                compareObjectsRecursively(modifications, processedObjects, currentObjectTree, key,
                        signedFirst ? signedRevObject : finalRevObject, signedFirst ? finalRevObject : signedRevObject);
            }
        }
    }

    private boolean isProcessedReference(Set<String> processedObjects, PdfObjectTree objectTree,
                                                String key, Number objectNumber) {
        return processedObjects.contains(key + objectNumber) || objectTree.isProcessedReference(objectNumber);
    }

    private void addProcessedReference(Set<String> processedObjects, PdfObjectTree objectTree,
                                              String key, Number objectNumber) {
        if (objectNumber != null) {
            processedObjects.add(key + objectNumber);
            objectTree.addReference(objectNumber);
        }
    }

    private void compareDictStreams(Set<ObjectModification> modifications, PdfObjectTree objectTree,
                                           PdfDict signedDict, PdfDict finalDict) {
        final PdfObjectTree currentObjectTree = objectTree.copy();
        currentObjectTree.setStream();

        byte[] signedStream = getStreamBytesSecurely(signedDict);
        byte[] finalBytes = getStreamBytesSecurely(finalDict);
        if (Utils.isArrayEmpty(signedStream) && Utils.isArrayNotEmpty(finalBytes)) {
            modifications.add(ObjectModification.create(currentObjectTree, finalDict));
            if (LOG.isDebugEnabled()) {
                LOG.debug("A stream has been added '{}'.", currentObjectTree);
            }

        } else if (Utils.isArrayNotEmpty(signedStream) && Utils.isArrayEmpty(finalBytes)) {
            modifications.add(ObjectModification.delete(currentObjectTree, signedDict));
            if (LOG.isDebugEnabled()) {
                LOG.debug("A stream has been removed '{}'.", currentObjectTree);
            }

        } else if (Utils.isArrayNotEmpty(signedStream) && Utils.isArrayNotEmpty(finalBytes)) {
            if (!Arrays.equals(signedStream, finalBytes)) {
                modifications.add(ObjectModification.modify(currentObjectTree, signedDict, finalDict));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("A stream has been modified '{}'.", currentObjectTree);
                }
            }
        }
    }

    private byte[] getStreamBytesSecurely(PdfDict pdfDict) {
        try {
            return pdfDict.getStreamBytes();

        } catch (IOException e) {
            LOG.debug("Unable to compare underlying stream binaries. Reason : {}", e.getMessage());
            return DSSUtils.EMPTY_BYTE_ARRAY;
        }
    }

}
