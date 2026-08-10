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

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Used to categorize {@code ObjectModification}s to four different categories.
 *
 */
public class PdfObjectModificationsFilter {

    private static final Logger LOG = LoggerFactory.getLogger(PdfObjectModificationsFilter.class);

    /**
     * Default constructor
     */
    public PdfObjectModificationsFilter() {
        // empty
    }

    /**
     * Categorizes the given collection of {@code ObjectModification}s to various categories and
     * returns {@code PdfObjectModifications} containing the result of filtering.
     *
     * @param objectModifications a collection of {@link ObjectModification}s to be categorized
     * @return {@link PdfObjectModifications}
     */
    public PdfObjectModifications filter(final Collection<ObjectModification> objectModifications) {
        final PdfObjectModifications pdfObjectModifications = new PdfObjectModifications();
        if (Utils.isCollectionEmpty(objectModifications)) {
            return pdfObjectModifications;
        }

        for (ObjectModification objectModification : objectModifications) {
            if (skipChange(objectModification)) {
                continue;
            }
            if (isExtensionChange(objectModification)) {
                pdfObjectModifications.addSecureChange(objectModification);
            } else if (isSignatureOrFormFillChange(objectModification)) {
                pdfObjectModifications.addFormFillInAndSignatureCreationChange(objectModification);
            } else if (isAnnotationChange(objectModification)) {
                pdfObjectModifications.addAnnotCreationChange(objectModification);
            } else {
                pdfObjectModifications.addUndefinedChange(objectModification);
            }
        }

        return pdfObjectModifications;
    }

    /**
     * This method allows to skip some modification occurring in PdfBox and OpenPDF
     *
     * @param objectModification {@link ObjectModification}
     * @return TRUE if the modification should be skipped, FALSE otherwise
     */
    protected boolean skipChange(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        if (PdfObjectModificationType.DELETION.equals(objectModification.getActionType()) &&
                PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(lastKey)) {
            return true;
        } else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
                PAdESConstants.ANNOT_FLAG.equals(lastKey)) {
            return true;
        } else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
                PAdESConstants.TYPE_NAME.equals(lastKey)) {
            return true;
        } else if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
                PAdESConstants.ITEXT_NAME.equals(lastKey)) {
            return true;
        }
        return false;
    }

    /**
     * Returns whether the modification corresponds to a signature augmentation
     * (such as DocTimeStamp or DSS dictionary creation)
     *
     * @param objectModification {@link ObjectModification}
     * @return TRUE if the modification corresponds to augmentation process, FALSE otherwise
     */
    protected boolean isExtensionChange(ObjectModification objectModification) {
        if (isDSSDictionaryChange(objectModification)) {
            return true;
        } else if (isDocTimeStampAdded(objectModification)) {
            return true;
        } else if (isDocumentExtension(objectModification)) {
            return true;
        } else if (isVersionChange(objectModification)) {
            return true;
        } else if (isExtensionsChange(objectModification)) {
            return true;
        } else if (isMetaDataChange(objectModification)) {
            return true;
        } else if (isStructTreeRootChange(objectModification)) {
            return true;
        } else if (isAnnotsArrayCreationForTimestamp(objectModification)) {
            return true;
        } else if (isNewTimestampCreation(objectModification)) {
            if (isEmptyAnnotFill(objectModification)) {
                return true;
            } else if (isFontCreationChange(objectModification)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDSSDictionaryChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.DSS_DICTIONARY_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDocTimeStampAdded(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        if (isAnnotsKey(key)) {
            PdfObject addedObject = objectModification.getFinalObject();
            if (addedObject instanceof PdfDict) {
                PdfObject valueObject = ((PdfDict) addedObject).getObject(PAdESConstants.VALUE_NAME);
                if (valueObject instanceof PdfDict && isDocTimeStamp((PdfDict) valueObject)) {
                    return true;
                }
            }
        } else if (isValueKey(key)) {
            PdfObject addedObject = objectModification.getFinalObject();
            if (addedObject instanceof PdfDict && isDocTimeStamp((PdfDict) addedObject)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean isSignature(PdfDict pdfDict) {
        return isObjectOfType(pdfDict, PAdESConstants.SIGNATURE_TYPE);
    }

    private boolean isDocTimeStamp(PdfDict pdfDict) {
        return isObjectOfType(pdfDict, PAdESConstants.TIMESTAMP_TYPE);
    }

    private boolean isObjectOfType(PdfObject pdfObject, String typeValue) {
        if (pdfObject instanceof PdfDict) {
            PdfObject typeObject = ((PdfDict) pdfObject).getObject(PAdESConstants.TYPE_NAME);
            if (typeObject != null && typeValue.equals(typeObject.getValue())) {
                return true;
            }
            PdfObject ftObject = ((PdfDict) pdfObject).getObject(PAdESConstants.FT_NAME);
            if (ftObject != null && typeValue.equals(ftObject.getValue())) {
                return true;
            }
        }
        return false;
    }

    private boolean isDocumentExtension(ObjectModification objectModification) {
        // can be relevant for /DSS or/and /DocTimeStamp incorporation
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PAdESConstants.EXTENSIONS_NAME.equals(key) && PAdESConstants.CATALOG_NAME.equals(parentKey);
    }

    /**
     * Returns whether the modification corresponds to a signature addition or a form fill
     * (such as DocTimeStamp or DSS dictionary creation)
     *
     * @param objectModification {@link ObjectModification}
     * @return TRUE if the modification corresponds to a signature addition or a form fill process, FALSE otherwise
     */
    protected boolean isSignatureOrFormFillChange(ObjectModification objectModification) {
        if (isCatalogPieceInfoChange(objectModification)) {
            return true;
        } else if (isCatalogPermsCreationChange(objectModification)) {
            return true;
        } else if (isCatalogNamesChange(objectModification)) {
            return true;
        } else if (isCatalogOutputIntentsChange(objectModification)) {
            return true;
        } else if (isAcroFormDictionaryChange(objectModification)) {
            return true;
        } else if (isAnnotsArrayCreationForSignature(objectModification)) {
            return true;
        } else if (isNewSignatureCreation(objectModification) ||
                (isWidgetModification(objectModification) && !isSigOrTstModification(objectModification))) {
            // new signature creation or form fill
            if (isFieldFilled(objectModification)) {
                return true;
            } else if (isFieldValueAssignmentChange(objectModification)) {
                return true;
            } else if (isEmptyAnnotFill(objectModification)) {
                return true;
            } else if (isAnnotsFill(objectModification)) {
                return true;
            } else if (isFieldAppearanceCreationChange(objectModification)) {
                return true;
            } else if (isFontCreationChange(objectModification)) {
                return true;
            }
        }
        return false;
    }

    private boolean isFieldFilled(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        if (PAdESConstants.VALUE_NAME.equals(key) && isAnnotChange(objectModification)) {
            return true;
        } else if (isAnnotChange(objectModification)) {
            Object addedObject = objectModification.getFinalObject();
            return addedObject instanceof PdfDict && isValueChange((PdfDict) addedObject);
        }
        return false;
    }

    private boolean isValueChange(PdfDict pdfDict) {
        return pdfDict.getAsDict(PAdESConstants.VALUE_NAME) != null;
    }

    private boolean isValueKey(String key) {
        return isOneOf(key, PAdESConstants.VALUE_NAME);
    }

    private boolean isAnnotChange(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (isAnnotsKey(lastKey) || isAnnotsKey(parentKey)) {
            return true;
        }

        boolean isAnnotProcessing = false;
        boolean resetChain = false;
        for (String key : objectModification.getObjectTree().getKeyChain()) {
            if (resetChain) {
                isAnnotProcessing = false;
                resetChain = false;
            }
            if (isAnnotsKey(key)) {
                isAnnotProcessing = true;
            } else if (!isParentOrKid(key)) {
                resetChain = true;
            }
        }
        return isAnnotProcessing && (isParentOrKid(lastKey) || isParentOrKid(parentKey));
    }

    private boolean isAnnotsKey(String key) {
        return isOneOf(key, PAdESConstants.ANNOTS_NAME, PAdESConstants.FIELDS_NAME);
    }

    private boolean isParentOrKid(String key) {
        return isOneOf(key, PAdESConstants.PARENT_NAME, PAdESConstants.KIDS_NAME);
    }

    private boolean isAnnotsFill(ObjectModification objectModification) {
        if (!PdfObjectModificationType.DELETION.equals(objectModification.getActionType())) {
            String lastKey = objectModification.getObjectTree().getLastKey();
            return isAnnotChange(objectModification) && !isAnnotsKey(lastKey);
        }
        return false;
    }

    private boolean isAnnotsArrayCreation(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        return PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) && isAnnotsKey(lastKey)
                && objectModification.getFinalObject() instanceof PdfArray;
    }

    private boolean isAnnotsArrayCreationForSignature(ObjectModification objectModification) {
        return isAnnotsArrayCreation(objectModification) && checkForFieldsOfType(objectModification, PAdESConstants.SIGNATURE_TYPE);
    }

    private boolean isAnnotsArrayCreationForTimestamp(ObjectModification objectModification) {
        return isAnnotsArrayCreation(objectModification) && checkForFieldsOfType(objectModification, PAdESConstants.TIMESTAMP_TYPE);
    }

    private boolean checkForFieldsOfType(ObjectModification objectModification, String fieldType) {
        PdfObject annots = objectModification.getFinalObject();
        if (!(annots instanceof PdfArray)) {
            return false;
        }
        PdfArray annotsArray = (PdfArray) annots;
        for (int i = 0; i < annotsArray.size(); i++) {
            PdfObject annotObject = annotsArray.getObject(i);
            if (!isObjectOfType(annotObject, fieldType)) {
                return false;
            }
        }
        return true;
    }

    private boolean isFieldAppearanceCreationChange(ObjectModification objectModification) {
        boolean appearanceDictChangeFound = false;
        boolean annotChangeFound = false;
        if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType())) {
            for (String chainKey : objectModification.getObjectTree().getKeyChain()) {
                if (isAnnotsKey(chainKey)) {
                    annotChangeFound = true;
                } else if (PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(chainKey)) {
                    appearanceDictChangeFound = true;
                    break;
                }
            }
        }
        return appearanceDictChangeFound && annotChangeFound;
    }

    private boolean isFieldValueAssignmentChange(ObjectModification objectModification) {
        boolean appearanceDictChangeFound = false;
        boolean annotChangeFound = false;
        if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType())) {
            for (String chainKey : objectModification.getObjectTree().getKeyChain()) {
                if (isAnnotsKey(chainKey)) {
                    annotChangeFound = true;
                } else if (PAdESConstants.VALUE_NAME.equals(chainKey)) {
                    appearanceDictChangeFound = true;
                    break;
                }
            }
        }
        return appearanceDictChangeFound && annotChangeFound;
    }

    private boolean isEmptyAnnotFill(ObjectModification objectModification) {
        boolean appearanceDictChangeFound = false;
        for (String chainKey : objectModification.getObjectTree().getKeyChain()) {
            if (PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(chainKey)) {
                appearanceDictChangeFound = true;
            } else if (appearanceDictChangeFound && PAdESConstants.NORMAL_APPEARANCE_NAME.equals(chainKey)) {
                return true;
            }
        }
        return false;
    }

    private boolean isNewSignatureCreation(ObjectModification objectModification) {
        return checkRecursivelyForNewSignatureCreation(objectModification, PAdESConstants.SIGNATURE_TYPE);
    }

    private boolean isNewTimestampCreation(ObjectModification objectModification) {
        return checkRecursivelyForNewSignatureCreation(objectModification, PAdESConstants.TIMESTAMP_TYPE);
    }

    private boolean checkRecursivelyForNewSignatureCreation(ObjectModification objectModification, String targetType) {
        return checkRecursivelyForNewSignatureCreation(objectModification.getOriginalObject(), objectModification.getFinalObject(), targetType, new HashSet<>());
    }

    private boolean checkRecursivelyForNewSignatureCreation(PdfObject originalObject, PdfObject finalObject, String targetType, Set<PdfObjectKey> processedObjects) {
        PdfObject originalSigValue = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getObject(PAdESConstants.VALUE_NAME) : null;
        PdfObject finalSigValue = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObject(PAdESConstants.VALUE_NAME) : null;
        if (originalSigValue == null && isObjectOfType(finalSigValue, targetType)) {
            return true;
        }

        PdfObjectKey finalParentKey = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObjectKey(PAdESConstants.PARENT_NAME) : null;
        if (processedObjects.contains(finalParentKey)) {
            return false;
        }

        PdfObject originalParent = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        PdfObject finalParent = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        if (finalParent != null) {
            processedObjects.add(finalParentKey);
            return checkRecursivelyForNewSignatureCreation(originalParent, finalParent, targetType, processedObjects);
        }

        originalParent = originalObject != null ? originalObject.getParent() : null;
        finalParent = finalObject != null ? finalObject.getParent() : null;
        if (originalParent == null && finalParent == null) {
            return false;
        }
        return checkRecursivelyForNewSignatureCreation(originalParent, finalParent, targetType, processedObjects);
    }

    private boolean isWidgetModification(ObjectModification objectModification) {
        return checkRecursivelyForAnnotOfType(objectModification.getOriginalObject(), objectModification.getFinalObject(), PAdESConstants.SUBTYPE_WIDGET, new HashSet<>());
    }

    private boolean isSigOrTstModification(ObjectModification objectModification) {
        return checkRecursivelyForExistingSigOrTstFieldType(objectModification.getOriginalObject(), objectModification.getFinalObject(), new HashSet<>());
    }

    private boolean checkRecursivelyForExistingSigOrTstFieldType(PdfObject originalObject, PdfObject finalObject, Set<PdfObjectKey> processedObjects) {
        String originalType = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getNameValue(PAdESConstants.TYPE_NAME) : null;
        String originalFieldType = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getNameValue(PAdESConstants.FT_NAME) : null;

        // evaluation goes from bottom to top. Stop at the first non-sig /Annot entry
        if (originalFieldType != null) {
            if (PAdESConstants.SIGNATURE_TYPE.equals(originalFieldType) || PAdESConstants.TIMESTAMP_TYPE.equals(originalFieldType)) {
                return ((PdfDict) originalObject).getAsDict(PAdESConstants.VALUE_NAME) != null;
            }
            return false;
        }
        if (PAdESConstants.TYPE_ANNOT.equals(originalType)) {
            return false;
        }

        PdfObjectKey finalParentKey = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObjectKey(PAdESConstants.PARENT_NAME) : null;
        if (processedObjects.contains(finalParentKey)) {
            return false;
        }

        PdfObject originalParent = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        PdfObject finalParent = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        if (finalParent != null) {
            processedObjects.add(finalParentKey);
            return checkRecursivelyForExistingSigOrTstFieldType(originalParent, finalParent, processedObjects);
        }

        originalParent = originalObject != null ? originalObject.getParent() : null;
        finalParent = finalObject != null ? finalObject.getParent() : null;
        if (originalParent == null && finalParent == null) {
            return false;
        }
        return checkRecursivelyForExistingSigOrTstFieldType(originalParent, finalParent, processedObjects);
    }

    private boolean checkRecursivelyForAnnotOfType(PdfObject originalObject, PdfObject finalObject, String targetType, Set<PdfObjectKey> processedObjects) {
        String originalType = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getNameValue(PAdESConstants.TYPE_NAME) : null;
        String finalType = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getNameValue(PAdESConstants.TYPE_NAME) : null;
        String originalSubtype = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getNameValue(PAdESConstants.SUBTYPE_NAME) : null;
        String finalSubtype = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getNameValue(PAdESConstants.SUBTYPE_NAME) : null;

        if (originalObject != null && finalObject != null) {
            if (PAdESConstants.TYPE_ANNOT.equals(originalType) || PAdESConstants.TYPE_ANNOT.equals(finalType)) {
                return targetType.equals(originalSubtype) && originalType.equals(finalType) && originalSubtype.equals(finalSubtype);
            }
        }
        if (PAdESConstants.TYPE_ANNOT.equals(originalType)) {
            return targetType.equals(originalSubtype);
        }
        if (PAdESConstants.TYPE_ANNOT.equals(finalType)) {
            return targetType.equals(finalSubtype);
        }

        PdfObjectKey finalParentKey = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObjectKey(PAdESConstants.PARENT_NAME) : null;
        if (processedObjects.contains(finalParentKey)) {
            return false;
        }

        PdfObject originalParent = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        PdfObject finalParent = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObject(PAdESConstants.PARENT_NAME) : null;
        if (finalParent != null) {
            processedObjects.add(finalParentKey);
            return checkRecursivelyForAnnotOfType(originalParent, finalParent, targetType, processedObjects);
        }

        originalParent = originalObject != null ? originalObject.getParent() : null;
        finalParent = finalObject != null ? finalObject.getParent() : null;
        if (originalParent == null && finalParent == null) {
            return false;
        }
        return checkRecursivelyForAnnotOfType(originalParent, finalParent, targetType, processedObjects);
    }

    private boolean isVersionChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
                PAdESConstants.VERSION_NAME.equals(key) &&
                isOneOf(parentKey, PAdESConstants.CATALOG_NAME, PAdESConstants.DATA_NAME, PAdESConstants.ROOT_NAME);
    }

    private boolean isExtensionsChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.EXTENSIONS_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private boolean isCatalogPieceInfoChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.PIECE_INFO_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private boolean isCatalogPermsCreationChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        return PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                PAdESConstants.PERMS_NAME.equals(key);
    }

    private boolean isCatalogNamesChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.NAMES_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private boolean isCatalogOutputIntentsChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        return PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                PAdESConstants.OUTPUT_INTENTS_NAME.equals(key);
    }

    private boolean isMetaDataChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PAdESConstants.METADATA_NAME.equals(key) || PAdESConstants.METADATA_NAME.equals(parentKey);
    }

    private boolean isStructTreeRootChange(ObjectModification objectModification) {
        /*
         * The validation of the StructTreeRoot modifications is aligned with "allowed to be modified" changes,
         * of the <a href="https://github.com/itext/itext-java/blob/9.2.0/sign/src/main/java/com/itextpdf/signatures/validation/DocumentRevisionsValidator.java#L687">iText library</a>.
         */
        boolean isStructTreeRoot = false;
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        String lastKey = objectModification.getObjectTree().getLastKey();
        PdfObjectModificationType actionType = objectModification.getActionType();
        for (String key : keyChain) {
            if (PAdESConstants.STRUCT_TREE_ROOT_NAME.equals(key)) {
                isStructTreeRoot = true;

            } else if (isStructTreeRoot && isOneOf(key,
                    PAdESConstants.STRUCT_TREE_ROOT_ID_TREE_NAME,
                    PAdESConstants.STRUCT_TREE_ROOT_PARENT_TREE_NAME,
                    PAdESConstants.STRUCT_TREE_ROOT_PARENT_TREE_NEXT_KEY_NAME)) {
                return true;

            } else if (isStructTreeRoot && PAdESConstants.STRUCT_TREE_ROOT_K_NAME.equals(key) && PAdESConstants.STRUCT_TREE_ROOT_K_NAME.equals(lastKey) &&
                    (PdfObjectModificationType.CREATION == actionType || PdfObjectModificationType.DELETION == actionType)) {
                return true;

            } else {
                isStructTreeRoot = false;
            }
        }
        return false;
    }

    private boolean isAcroFormDictionaryChange(ObjectModification objectModification) {
        boolean acroFormReached = false;
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (acroFormReached) {
                if (isOneOf(key, PAdESConstants.DOCUMENT_APPEARANCE_NAME,
                        PAdESConstants.DOCUMENT_RESOURCES_NAME, PAdESConstants.SIG_FLAGS_NAME)) {
                    return true;
                }
            }
            acroFormReached = PAdESConstants.ACRO_FORM_NAME.equals(key);
        }
        return false;
    }

    private boolean isFontCreationChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                (PAdESConstants.FONT_NAME.equals(key) || PAdESConstants.FONT_NAME.equals(parentKey));
    }

    private String getParentKey(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        if (keyChain.size() > 1) {
            return keyChain.get(keyChain.size() - 2);
        }
        return null;
    }

    /**
     * Returns whether the modification corresponds to an annotation change
     * (such as DocTimeStamp or DSS dictionary creation)
     *
     * @param objectModification {@link ObjectModification}
     * @return TRUE if the modification corresponds to an annotation change process, FALSE otherwise
     */
    protected boolean isAnnotationChange(ObjectModification objectModification) {
        if (isSigOrTstModification(objectModification)) {
            return false;
        }

        if (isAnnotsArrayCreation(objectModification)) {
            return true;
        } else if (isEmptyAnnotFill(objectModification)) {
            return true;
        } else if (isAnnotsFill(objectModification)) {
            return true;
        } else if (isFieldAppearanceCreationChange(objectModification)) {
            return true;
        } else if (isFontCreationChange(objectModification)) {
            return true;
        }
        return isOtherAnnotChange(objectModification);
    }

    private boolean isOtherAnnotChange(ObjectModification objectModification) {
        if (isAnnotChange(objectModification)) {
            if (PdfObjectModificationType.DELETION.equals(objectModification.getActionType()) &&
                    objectModification.getOriginalObject() instanceof PdfDict) {
                PdfDict pdfDict = (PdfDict) objectModification.getOriginalObject();
                PdfObject valueObject = pdfDict.getObject(PAdESConstants.VALUE_NAME);
                if (valueObject instanceof PdfDict) {
                    PdfDict valueDict = (PdfDict) valueObject;
                    return !isSignature(valueDict) && !isDocTimeStamp(valueDict);
                }
            }
            return true;
        }
        return false;
    }

    private boolean isOneOf(String key, String... toCompare) {
        return Arrays.asList(toCompare).contains(key);
    }

}
