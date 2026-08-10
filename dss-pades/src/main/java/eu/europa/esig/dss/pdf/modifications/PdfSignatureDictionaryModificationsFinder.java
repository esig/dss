package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.europa.esig.dss.pdf.PAdESConstants.ACTION_WIDGET_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.ADDITIONAL_ACTIONS_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.ANNOT_FLAG;
import static eu.europa.esig.dss.pdf.PAdESConstants.APPEARANCE_CHARACTERISTICS_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.APPEARANCE_DICTIONARY_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.ASSOCIATED_FILES_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.AS_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.CONTENTS_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.FIELD_ALTERNATIVE_NAME_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.FIELD_MAPPING_NAME_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.FIELD_NAME_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.FT_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.LOCK_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.OPTIONAL_CONTENT_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.PAGE_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.PARENT_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.RECT_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.SUBTYPE_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.SV_NAME;
import static eu.europa.esig.dss.pdf.PAdESConstants.TYPE_ANNOT;
import static eu.europa.esig.dss.pdf.PAdESConstants.VALUE_NAME;

/**
 * Looks for object modifications occurred in a signature dictionary, including associated signature fields.
 * NOTE: This class operates over a "white-listed" entries to be verified.
 * It does not verify all entries within a signature field, as those may change.
 *
 */
public class PdfSignatureDictionaryModificationsFinder extends DefaultPdfObjectModificationsFinder {

    private static final Logger LOG = LoggerFactory.getLogger(PdfSignatureDictionaryModificationsFinder.class);

    /**
     * Collection of fields to be evaluated during the object comparison
     */
    private static final List<String> CRITICAL_SIGNATURE_FIELD_ENTRIES = Arrays.asList(
            TYPE_ANNOT, SUBTYPE_NAME, RECT_NAME, CONTENTS_NAME, PAGE_NAME, ANNOT_FLAG, APPEARANCE_DICTIONARY_NAME,
            AS_NAME, OPTIONAL_CONTENT_NAME, ASSOCIATED_FILES_NAME, APPEARANCE_CHARACTERISTICS_NAME, ACTION_WIDGET_NAME,
            ADDITIONAL_ACTIONS_NAME, FT_NAME, FIELD_NAME_NAME, FIELD_ALTERNATIVE_NAME_NAME, FIELD_MAPPING_NAME_NAME,
            VALUE_NAME, PARENT_NAME, LOCK_NAME, SV_NAME
    );

    /**
     * Default constructor
     */
    public PdfSignatureDictionaryModificationsFinder() {
        // empty
    }

    /**
     * Compares {@code signedSigDictionary} with {@code finalSigDictionary}
     *
     * @param signedSigDictionary {@link PdfSigDictWrapper} representing a signature dictionary
     *                            extracted from the signed revision
     * @param finalSigDictionary {@link PdfSigDictWrapper} representing a signature dictionary
     *                            extracted from the final revision
     * @return {@link PdfObjectModifications}
     */
    public PdfObjectModifications compareSignatureDictionaries(PdfSigDictWrapper signedSigDictionary, PdfSigDictWrapper finalSigDictionary) {
        final Set<ObjectModification> objectModifications = new HashSet<>();
        PdfObjectTree objectTree = new PdfObjectTree();

        List<PdfSignatureField> signedSignatureFields = signedSigDictionary.getSignatureFields();
        List<PdfSignatureField> finalSignatureFields = finalSigDictionary.getSignatureFields();

        List<String> finalRevFieldNames = getFieldNames(finalSignatureFields);
        if (Utils.collectionSize(signedSignatureFields) > Utils.collectionSize(finalSignatureFields)) {
            signedSignatureFields.stream().filter(f -> !finalRevFieldNames.contains(f.getFullyQualifiedName()))
                    .forEach(f -> {
                        LOG.warn("No matching signature field '{}' found in the final revision!", f.getFullyQualifiedName());
                        objectModifications.add(ObjectModification.delete(objectTree, f.getDictionary()));
                    });
        }

        for (int i = 0; i < finalSignatureFields.size(); i++) {
            PdfSignatureField finalSignatureField = finalSignatureFields.get(i);
            PdfSignatureField revisionSignatureField = signedSignatureFields.stream()
                    .filter(signatureField -> Objects.equals(finalSignatureField.getFullyQualifiedName(), signatureField.getFullyQualifiedName()))
                    .findFirst()
                    .orElse(null);

            PdfObjectTree sigFieldObjectTree = objectTree.copy();
            sigFieldObjectTree.addKey(finalSignatureField.getFullyQualifiedName());
            if (revisionSignatureField == null) {
                LOG.warn("No matching signature field '{}' found in the signed revision!", finalSignatureField.getFullyQualifiedName());
                objectModifications.add(ObjectModification.create(sigFieldObjectTree, finalSignatureField.getDictionary()));
                continue;
            }

            PdfDict revisionDict = revisionSignatureField.getDictionary();
            PdfDict finalDict = finalSignatureField.getDictionary();

            Set<String> sigFieldDictNames = getFieldsToCompare(revisionDict);
            Set<String> finalFieldDictNames = getFieldsToCompare(finalDict);
            if (Utils.collectionSize(sigFieldDictNames) > Utils.collectionSize(finalFieldDictNames)) {
                sigFieldDictNames.stream().filter(f -> !finalFieldDictNames.contains(f))
                        .forEach(f -> {
                            LOG.warn("No matching signature field's object '{}' found in the final revision!", f);
                            objectModifications.add(ObjectModification.delete(sigFieldObjectTree, revisionDict.getObject(f)));
                        });
            }

            for (String key : finalFieldDictNames) {
                PdfObjectTree dictObjectTree = sigFieldObjectTree.copy();
                dictObjectTree.addKey(key);

                if (VALUE_NAME.equals(key)) {
                    // NOTE: /V dictionary shall be checked only once (same for given signature fields)
                    if (i == 0) {
                        compareObjectsRecursively(objectModifications, new HashSet<>(), dictObjectTree, key,
                                revisionDict.getObject(key), finalDict.getObject(key));
                    }

                } else if (Arrays.asList(PARENT_NAME, PAGE_NAME).contains(key)) {
                    // NOTE : only indirect references are compared for the following objects
                    PdfObjectKey revisionObject = revisionDict.getObjectKey(key);
                    PdfObjectKey finalObject = finalDict.getObjectKey(key);
                    if (revisionObject == null) {
                        LOG.warn("The signature field's '{}' object '{}' is not present in the signed revision!",
                                key, finalSignatureField.getFullyQualifiedName());
                        objectModifications.add(ObjectModification.delete(dictObjectTree, finalDict.getObject(key)));
                    } else if (finalObject == null) {
                        LOG.warn("The signature field's '{}' object '{}' is not present in the final revision!",
                                key, revisionSignatureField.getFullyQualifiedName());
                                objectModifications.add(ObjectModification.create(dictObjectTree, revisionDict.getObject(key)));
                    } else if (revisionObject.getNumber() != finalObject.getNumber()) {
                        LOG.warn("The signature field's '{}' object is not equal to the signed revision version " +
                                "in the signature field with name '{}'!", key, finalSignatureField.getFullyQualifiedName());
                        objectModifications.add(ObjectModification.modify(dictObjectTree, revisionDict.getObject(key), finalDict.getObject(key)));
                    }

                } else {
                    compareObjectsRecursively(objectModifications, new HashSet<>(), dictObjectTree, key,
                            revisionDict.getObject(key), finalDict.getObject(key));
                }
            }
        }

        if (Utils.isCollectionNotEmpty(objectModifications)) {
            removeReferenceData(objectModifications);
        }
        return new PdfObjectModificationsFilter().filter(objectModifications);
    }

    private Set<String> getFieldsToCompare(PdfDict dict) {
        /*
         * 12.5.2 Annotation dictionaries
         * A PDF reader shall render the appearance dictionary without regard to any other keys and values in
         * the annotation dictionary and shall ignore the values of the C, IC, Border, BS, BE, BM, CA, ca, H, DA, Q,
         * DS, LE, LL, LLE, and Sy keys.
         *
         * NOTE: DSS skips also some other irrelevant fields
         */
        Set<String> fieldNames = new HashSet<>(Arrays.asList(dict.list()));
        fieldNames.retainAll(CRITICAL_SIGNATURE_FIELD_ENTRIES);
        return fieldNames;
    }

    private void removeReferenceData(Collection<ObjectModification> modifications) {
        // /Reference /Data dictionary contains references to PDF objects covered by the signature.
        // The changes inside do not impact signature validity directly.
        if (Utils.isCollectionNotEmpty(modifications)) {
            modifications.removeIf(objectModification ->
                    objectModification.getObjectTree().getKeyChain().contains(PAdESConstants.REFERENCE_NAME) &&
                            objectModification.getObjectTree().getKeyChain().contains(PAdESConstants.DATA_NAME));
        }
    }

    private List<String> getFieldNames(List<PdfSignatureField> signatureFields) {
        return signatureFields.stream().map(PdfSignatureField::getFullyQualifiedName).collect(Collectors.toList());
    }

}
