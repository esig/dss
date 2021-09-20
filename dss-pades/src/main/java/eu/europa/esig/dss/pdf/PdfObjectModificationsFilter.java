package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;

import java.util.Collection;
import java.util.List;

/**
 * This class is used to filter a collection of {@code ObjectModification}s
 *
 */
public class PdfObjectModificationsFilter {

    /** A list of object modifications to be filtered */
    private final Collection<ObjectModification> objectModifications;

    /**
     * Default constructor
     *
     * @param objectModifications a collection of {@link ObjectModification}s
     */
    public PdfObjectModificationsFilter(Collection<ObjectModification> objectModifications) {
        this.objectModifications = objectModifications;
    }

    /**
     * Filters the collection of {@code ObjectModification}s to various categories
     *
     * @return {@link PdfObjectModifications}
     */
    public PdfObjectModifications filter() {
        final PdfObjectModifications pdfObjectModifications = new PdfObjectModifications();

        for (ObjectModification objectModification : objectModifications) {
            if (skipChange(objectModification)) {
                continue;
            }
            if (isExtensionChange(objectModification)) {
                pdfObjectModifications.addSecureChange(objectModification);
            } else if (isSignatureOrFormFillChange(objectModification)) {
                pdfObjectModifications.addFormFillInAndSignatureCreationChange(objectModification);
            } else if (isAnnotationCreationChange(objectModification)) {
                pdfObjectModifications.addAnnotCreationChange(objectModification);
            } else {
                pdfObjectModifications.addUndefinedChange(objectModification);
            }
        }

        return pdfObjectModifications;
    }

    /*
     * Note for developers:
     * This method allows to skip some modification occurring in PdfBox and OpenPDF
     */
    private static boolean skipChange(ObjectModification objectModification) {
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

    private static boolean isExtensionChange(ObjectModification objectModification) {
        if (isDSSDictionaryChange(objectModification)) {
            return true;
        } else if (isDocTimeStampAdded(objectModification)) {
            return true;
        } else if (isDocumentExtension(objectModification)) {
            return true;
        } else if (isCatalogVersionChange(objectModification)) {
            return true;
        } else if (isCatalogExtensionsChange(objectModification)) {
            return true;
        }
        return false;
    }

    private static boolean isDSSDictionaryChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.DSS_DICTIONARY_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDocTimeStampAdded(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        if (isAnnotsKey(key)) {
            Object addedObject = objectModification.getFinalObject();
            if (addedObject instanceof PdfDict && isDocTimeStamp((PdfDict) addedObject)) {
                return true;
            }
            return false;
        }
        return false;
    }

    private static boolean isDocTimeStamp(PdfDict pdfDict) {
        final PdfDict vDict = pdfDict.getAsDict(PAdESConstants.VALUE_NAME);
        if (vDict != null) {
            String type = vDict.getNameValue(PAdESConstants.TYPE_NAME);
            if (PAdESConstants.TIMESTAMP_TYPE.equals(type)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDocumentExtension(ObjectModification objectModification) {
        // can be relevant for /DSS or/and /DocTimeStamp incorporation
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return PAdESConstants.EXTENSIONS_NAME.equals(key) && PAdESConstants.CATALOG_NAME.equals(parentKey);
    }

    private static boolean isSignatureOrFormFillChange(ObjectModification objectModification) {
        if (isFieldFilled(objectModification)) {
            return true;
        } else if (isAnnotsFill(objectModification)) {
            return true;
        } else if (isFieldAppearanceCreationChange(objectModification)) {
            return true;
        } else if (isMetaDataChange(objectModification)) {
            return true;
        } else if (isCatalogPieceInfoChange(objectModification)) {
            return true;
        } else if (isCatalogPermsCreationChange(objectModification)) {
            return true;
        } else if (isCatalogNamesChange(objectModification)) {
            return true;
        } else if (isAcroFormDictionaryChange(objectModification)) {
            return true;
        } else if (isFontCreationChange(objectModification)) {
            return true;
        }
        return false;
    }

    private static boolean isFieldFilled(ObjectModification objectModification) {
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

    private static boolean isValueChange(PdfDict pdfDict) {
        final PdfDict vDict = pdfDict.getAsDict(PAdESConstants.VALUE_NAME);
        if (vDict != null) {
            return true;
        }
        return false;
    }

    private static boolean isAnnotsKey(String key) {
        return PAdESConstants.ANNOTS_NAME.equals(key) || PAdESConstants.FIELDS_NAME.equals(key) ||
                PAdESConstants.PARENT_NAME.equals(key);
    }

    private static boolean isAnnotsFill(ObjectModification objectModification) {
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

    private static boolean isFieldAppearanceCreationChange(ObjectModification objectModification) {
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

    private static boolean isCatalogVersionChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (PdfObjectModificationType.MODIFICATION.equals(objectModification.getActionType()) &&
                PAdESConstants.VERSION_NAME.equals(key) && PAdESConstants.CATALOG_NAME.equals(parentKey)) {
            return true;
        }
        return false;
    }

    private static boolean isCatalogExtensionsChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.EXTENSIONS_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCatalogPieceInfoChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.PIECE_INFO_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCatalogPermsCreationChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                PAdESConstants.PERMS_NAME.equals(key)) {
            return true;
        }
        return false;
    }

    private static boolean isCatalogNamesChange(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.NAMES_NAME.equals(key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isMetaDataChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (PAdESConstants.METADATA_NAME.equals(key) || PAdESConstants.METADATA_NAME.equals(parentKey)) {
            return true;
        }
        return false;
    }

    private static boolean isAcroFormDictionaryChange(ObjectModification objectModification) {
        boolean containsAcroForm = false;
        boolean containsResourseDict = false;
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        for (String key : keyChain) {
            if (PAdESConstants.ACRO_FORM_NAME.equals(key)) {
                containsAcroForm = true;
            } else if (PAdESConstants.DOCUMENT_APPEARANCE_NAME.equals(key) ||
                    PAdESConstants.DOCUMENT_RESOURCES_NAME.equals(key) || PAdESConstants.SIG_FLAGS_NAME.equals(key)) {
                containsResourseDict = true;
            }
        }
        return containsAcroForm && containsResourseDict;
    }

    private static boolean isFontCreationChange(ObjectModification objectModification) {
        String key = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        if (PdfObjectModificationType.CREATION.equals(objectModification.getActionType()) &&
                (PAdESConstants.FONT_NAME.equals(key) || PAdESConstants.FONT_NAME.equals(parentKey))) {
            return true;
        }
        return false;
    }

    private static String getParentKey(ObjectModification objectModification) {
        List<String> keyChain = objectModification.getObjectTree().getKeyChain();
        if (keyChain.size() > 1) {
            return keyChain.get(keyChain.size() - 2);
        }
        return null;
    }

    private static boolean isAnnotationCreationChange(ObjectModification objectModification) {
        if (isAnnotCreation(objectModification)) {
            return true;
        }
        return false;
    }

    private static boolean isAnnotCreation(ObjectModification objectModification) {
        String lastKey = objectModification.getObjectTree().getLastKey();
        String parentKey = getParentKey(objectModification);
        return isAnnotsKey(lastKey) || isAnnotsKey(parentKey);
    }

}
