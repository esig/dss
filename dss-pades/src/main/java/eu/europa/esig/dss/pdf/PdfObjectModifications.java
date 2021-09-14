package eu.europa.esig.dss.pdf;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains a collection of {@code ObjectModification}s categorized by different groups
 *
 */
public class PdfObjectModifications {

    /**
     * Modifications that are not considered as changes in an incremental update
     * (DSS dictionary, DocTimeStamp creation)
     */
    private final List<ObjectModification> secureChanges = new ArrayList<>();

    /**
     * Changes that are acceptable for /DocMDP P=2 parameter level
     * (Filling in forms, instantiating page templates, and signing)
     */
    private final List<ObjectModification> formFillInAndSignatureCreationChanges = new ArrayList<>();

    /**
     * Changes that are acceptable for /DocMDP P=3 parameter level
     * (Annotation creation, deletion, and modification)
     */
    private final List<ObjectModification> annotCreationChanges = new ArrayList<>();

    /**
     * Other changes that should invalidate the signature
     */
    private final List<ObjectModification> undefinedChanges = new ArrayList<>();

    /**
     * Adds a secure change concerning signature augmentation (DSS dictionary, DocTimeStamp)
     *
     * @param objectModification {@link ObjectModification}
     */
    public void addSecureChange(ObjectModification objectModification) {
        secureChanges.add(objectModification);
    }

    /**
     * Adds a modification concerning form filling or a signature creation
     *
     * @param objectModification {@link ObjectModification}
     */
    public void addFormFillInAndSignatureCreationChange(ObjectModification objectModification) {
        formFillInAndSignatureCreationChanges.add(objectModification);
    }

    /**
     * Adds a modification concerning annotation creation, modification or deletion
     *
     * @param objectModification {@link ObjectModification}
     */
    public void addAnnotCreationChange(ObjectModification objectModification) {
        annotCreationChanges.add(objectModification);
    }

    /**
     * Adds an undefined modification
     *
     * @param objectModification {@link ObjectModification}
     */
    public void addUndefinedChange(ObjectModification objectModification) {
        undefinedChanges.add(objectModification);
    }

    /**
     * Returns a list of secure changes
     *
     * @return a list of {@link ObjectModification}s
     */
    public List<ObjectModification> getSecureChanges() {
        return secureChanges;
    }

    /**
     * Returns a list of form filling and signature creation related changes
     *
     * @return a list of {@link ObjectModification}s
     */
    public List<ObjectModification> getFormFillInAndSignatureCreationChanges() {
        return formFillInAndSignatureCreationChanges;
    }

    /**
     * Returns a list of annot creation/modification/deletion changes
     *
     * @return a list of {@link ObjectModification}s
     */
    public List<ObjectModification> getAnnotCreationChanges() {
        return annotCreationChanges;
    }

    /**
     * Returns a list of undefined changes
     *
     * @return a list of {@link ObjectModification}s
     */
    public List<ObjectModification> getUndefinedChanges() {
        return undefinedChanges;
    }

    /**
     * Checks whether the object is empty
     *
     * @return TRUE if no changes between signed and final revisions have been found, FALSE otherwise
     */
    public boolean isEmpty() {
        return secureChanges.isEmpty() && formFillInAndSignatureCreationChanges.isEmpty() &&
                annotCreationChanges.isEmpty() && undefinedChanges.isEmpty();
    }

}
