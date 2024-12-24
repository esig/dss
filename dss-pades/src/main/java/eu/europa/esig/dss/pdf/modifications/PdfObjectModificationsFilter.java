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
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

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
        } else if (isDocTimeStampEmptyFieldFill(objectModification)) {
            return true;
        } else if (isDocTimeStampEmptyFieldFontCreation(objectModification)) {
            return true;
        } else if (isDocumentExtension(objectModification)) {
            return true;
        } else if (isVersionChange(objectModification)) {
            return true;
        } else if (isExtensionsChange(objectModification)) {
            return true;
        } else if (isMetaDataChange(objectModification)) {
            return true;
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

    private boolean isObjectOfType(PdfDict pdfDict, String typeValue) {
        if (pdfDict != null) {
            PdfObject typeObject = pdfDict.getObject(PAdESConstants.TYPE_NAME);
            if (typeObject != null && typeValue.equals(typeObject.getValue())) {
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
        if (isFieldFilled(objectModification)) {
            return true;
        } else if (isAnnotsFill(objectModification)) {
            return true;
        } else if (isFieldAppearanceCreationChange(objectModification)) {
            return true;
        } else if (isSignatureEmptyFieldFill(objectModification)) {
            return true;
        } else if (isCatalogPieceInfoChange(objectModification)) {
            return true;
        } else if (isCatalogPermsCreationChange(objectModification)) {
            return true;
        } else if (isCatalogNamesChange(objectModification)) {
            return true;
        } else if (isCatalogOutputIntentsChange(objectModification)) {
            return true;
        } else if (isAcroFormDictionaryChange(objectModification)) {
            return true;
        } else if (isSignatureEmptyFieldFontCreation(objectModification)) {
            return true;
        }
        return false;
    }

    private boolean isFieldFilled(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (PAdESConstants.VALUE_NAME.equals(key) && isAnnotsKey(parentKey)) {
            return true;
        } else if (isAnnotsKey(key)) {
            Object addedObject = objectModification.getFinalObject();
            if (addedObject instanceof PdfDict && isValueChange((PdfDict) addedObject)) {
                return true;
            }
            return false;
        }
        return false;
    }

    private boolean isValueChange(PdfDict pdfDict) {
        return pdfDict.getAsDict(PAdESConstants.VALUE_NAME) != null;
    }

    private boolean isValueKey(String key) {
        return isOneOf(key, PAdESConstants.VALUE_NAME);
    }

    private boolean isAnnotsKey(String key) {
        return isOneOf(key, PAdESConstants.ANNOTS_NAME, PAdESConstants.FIELDS_NAME, PAdESConstants.PARENT_NAME);
    }

    private boolean isAnnotsFill(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (isAnnotsKey(lastKey) || isAnnotsKey(parentKey)) {
            return PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType());
        }
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) && isAnnotsKey(key)) {
                return true;
            }
        }
        return false;
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
                }
            }
        }
        return appearanceDictChangeFound && annotChangeFound;
    }

    private boolean isSignatureEmptyFieldFill(ObjectModification objectModification) {
        return isEmptyFieldFill(objectModification, PAdESConstants.SIGNATURE_TYPE);
    }

    private boolean isDocTimeStampEmptyFieldFill(ObjectModification objectModification) {
        return isEmptyFieldFill(objectModification, PAdESConstants.TIMESTAMP_TYPE);
    }

    private boolean isEmptyFieldFill(ObjectModification objectModification, String signatureType) {
        boolean appearanceDictChangeFound = false;
        boolean normalAppearanceFound = false;
        if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType())) {
            for (String chainKey : objectModification.getObjectTree().getKeyChain()) {
                if (PAdESConstants.APPEARANCE_DICTIONARY_NAME.equals(chainKey) && checkRecursivelyForNewSignatureCreation(objectModification, signatureType)) {
                    appearanceDictChangeFound = true;
                } else if (appearanceDictChangeFound && PAdESConstants.NORMAL_APPEARANCE_NAME.equals(chainKey)) {
                    normalAppearanceFound = true;
                }

                if (normalAppearanceFound) {
                    if (PAdESConstants.LENGTH_NAME.equals(chainKey)) {
                        return true;
                    } else if (isStreamFill(objectModification)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean checkRecursivelyForNewSignatureCreation(ObjectModification objectModification, String targetType) {
        return checkRecursivelyForNewSignatureCreation(objectModification.getOriginalObject(), objectModification.getFinalObject(), targetType);
    }

    private boolean checkRecursivelyForNewSignatureCreation(PdfObject originalObject, PdfObject finalObject, String targetType) {
        PdfObject originalSigValue = originalObject instanceof PdfDict ? ((PdfDict) originalObject).getObject(PAdESConstants.VALUE_NAME) : null;
        PdfObject finalSigValue = finalObject instanceof PdfDict ? ((PdfDict) finalObject).getObject(PAdESConstants.VALUE_NAME) : null;
        if (originalSigValue == null && finalSigValue instanceof PdfDict && isObjectOfType((PdfDict) finalSigValue, targetType)) {
            return true;
        }

        PdfObject originalParent = originalObject != null ? originalObject.getParent() : null;
        PdfObject finalParent = finalObject != null ? finalObject.getParent() : null;
        if (originalParent == null && finalParent == null) {
            return false;
        }
        return checkRecursivelyForNewSignatureCreation(originalParent, finalParent, targetType);
    }

    private boolean isStreamFill(ObjectModification objectModification) {
        try {
            Object originalObject = objectModification.getOriginalObject();
            Object finalObject = objectModification.getFinalObject();
            if (originalObject instanceof PdfDict && finalObject instanceof PdfDict) {
                PdfDict finalDict = (PdfDict) finalObject;
                byte[] finalBytes = finalDict.getStreamBytes();
                if (finalBytes != null && finalBytes.length != 0) {
                    return true;
                }
            }
        } catch (IOException e) {
            LOG.warn("Unable to evaluate stream modification from path '{}'. Reason : {}",
                    objectModification.getObjectTree(), e.getMessage(), e);
        }
        return false;
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

    private boolean isAcroFormDictionaryChange(ObjectModification objectModification) {
        boolean containsAcroForm = false;
        boolean containsResourseDict = false;
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.ACRO_FORM_NAME.equals(key)) {
                containsAcroForm = true;
            } else if (isOneOf(key, PAdESConstants.DOCUMENT_APPEARANCE_NAME,
                    PAdESConstants.DOCUMENT_RESOURCES_NAME, PAdESConstants.SIG_FLAGS_NAME)) {
                containsResourseDict = true;
            }
        }
        return containsAcroForm && containsResourseDict;
    }

    private boolean isSignatureEmptyFieldFontCreation(ObjectModification objectModification) {
        return isFontCreationChange(objectModification, PAdESConstants.SIGNATURE_TYPE);
    }

    private boolean isDocTimeStampEmptyFieldFontCreation(ObjectModification objectModification) {
        return isFontCreationChange(objectModification, PAdESConstants.TIMESTAMP_TYPE);
    }

    private boolean isFontCreationChange(ObjectModification objectModification, String signatureType) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                (PAdESConstants.FONT_NAME.equals(key) || PAdESConstants.FONT_NAME.equals(parentKey)) &&
                checkRecursivelyForNewSignatureCreation(objectModification, signatureType);
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
        return isAnnotChange(objectModification);
    }

    private boolean isAnnotChange(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (isAnnotsKey(lastKey) || isAnnotsKey(parentKey)) {
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
