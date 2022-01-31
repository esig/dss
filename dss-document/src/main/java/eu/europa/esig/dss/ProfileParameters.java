package eu.europa.esig.dss;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;
import java.util.List;

/**
 * This class manages the internal variables used in the process of creating of a signature and which allows to
 * accelerate the signature generation.
 *
 */
public class ProfileParameters implements Serializable {

    private static final long serialVersionUID = -8281291690615571695L;

    /** Cached detached contents (used for DETACHED signature creation or/and ASiC containers signing) */
    private List<DSSDocument> detachedContents;

    /**
     * Gets the detached contents
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets the detached contents
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

}
