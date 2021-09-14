package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.PdfObjectModificationType;

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
    public PdfObjectModificationType getType() {
        return objectModificationType;
    }

}
