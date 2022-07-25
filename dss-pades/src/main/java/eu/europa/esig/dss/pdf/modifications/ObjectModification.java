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
package eu.europa.esig.dss.pdf.modifications;

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;

import java.util.Objects;

/**
 * This object represents a modification occurred in a PDF document
 *
 */
public class ObjectModification {

    /** A collection of String keys representing a chain from a root to the actual object */
    private final PdfObjectTree objectTree;

    /** Signed revision modified object */
    private final Object originalObject;

    /** Final revision modified object */
    private final Object finalObject;

    /** Type of modification */
    private final PdfObjectModificationType objectModificationType;

    /**
     * Default constructor
     *
     * @param objectTree {@link PdfObjectTree}
     * @param originalObject signed revision object
     * @param finalObject final revision object
     * @param objectModificationType {@link PdfObjectModificationType}
     */
    private ObjectModification(PdfObjectTree objectTree, Object originalObject, Object finalObject, PdfObjectModificationType objectModificationType) {
        this.objectTree = objectTree;
        this.originalObject = originalObject;
        this.finalObject = finalObject;
        this.objectModificationType = objectModificationType;
    }

    /**
     * Creates {@code ObjectModification} for a new object creation change
     *
     * @param objectTree {@link PdfObjectTree}
     * @param finalObject final revision object
     * @return {@link ObjectModification}
     */
    public static ObjectModification create(PdfObjectTree objectTree, Object finalObject) {
        return new ObjectModification(objectTree, null, finalObject, PdfObjectModificationType.CREATION);
    }

    /**
     * Creates {@code ObjectModification} for an object removal change
     *
     * @param objectTree {@link PdfObjectTree}
     * @param originalObject signed revision object
     * @return {@link ObjectModification}
     */
    public static ObjectModification delete(PdfObjectTree objectTree, Object originalObject) {
        return new ObjectModification(objectTree, originalObject, null, PdfObjectModificationType.DELETION);
    }

    /**
     * Creates {@code ObjectModification} for an object modification change
     *
     * @param objectTree {@link PdfObjectTree}
     * @param originalObject signed revision object
     * @param finalObject final revision object
     * @return {@link ObjectModification}
     */
    public static ObjectModification modify(PdfObjectTree objectTree, Object originalObject, Object finalObject) {
        return new ObjectModification(objectTree, originalObject, finalObject, PdfObjectModificationType.MODIFICATION);
    }

    /**
     * Returns an object tree
     *
     * @return {@link PdfObjectTree}
     */
    public PdfObjectTree getObjectTree() {
        return objectTree;
    }

    /**
     * Gets a signed revision object
     *
     * @return original object
     */
    public Object getOriginalObject() {
        return originalObject;
    }

    /**
     * Gets a final document revision object
     *
     * @return final object
     */
    public Object getFinalObject() {
        return finalObject;
    }

    /**
     * Returns a corresponding object modification type
     *
     * @return {@link PdfObjectModificationType}
     */
    public PdfObjectModificationType getActionType() {
        return objectModificationType;
    }

    /**
     * Returns a name of the changed field object, when applicable
     *
     * NOTE: the object shall be a type of field. Returns null for other objects.
     *
     * @return {@link String} field name, when applicable. NULL otherwise.
     */
    public String getFieldName() {
        String fieldName = null;
        if (originalObject instanceof PdfDict) {
            fieldName = ((PdfDict) originalObject).getStringValue(PAdESConstants.FIELD_NAME_NAME);
        } else if (finalObject instanceof PdfDict) {
            fieldName = ((PdfDict) finalObject).getStringValue(PAdESConstants.FIELD_NAME_NAME);
        }
        return fieldName;
    }

    /**
     * Returns a type of concerned object, when applicable
     *
     * @return {@link String} type
     */
    public String getType() {
        String type = null;
        if (originalObject instanceof PdfDict) {
            type = getType((PdfDict) originalObject);
        } else if (finalObject instanceof PdfDict) {
            type = getType((PdfDict) finalObject);
        }
        return type;
    }

    private String getType(PdfDict pdfDict) {
        PdfDict valueDict = pdfDict.getAsDict(PAdESConstants.VALUE_NAME);
        if (valueDict != null) {
            return valueDict.getNameValue(PAdESConstants.TYPE_NAME);
        } else {
            return pdfDict.getNameValue(PAdESConstants.TYPE_NAME);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ObjectModification)) return false;

        ObjectModification that = (ObjectModification) o;

        if (!Objects.equals(objectTree, that.objectTree)) return false;
        return objectModificationType == that.objectModificationType;
    }

    @Override
    public int hashCode() {
        int result = objectTree != null ? objectTree.hashCode() : 0;
        result = 31 * result + (objectModificationType != null ? objectModificationType.hashCode() : 0);
        return result;
    }

}
