package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Parameters defining the configuration for creation of an ASiC container containing an evidence record document
 *
 */
public class ASiCContainerEvidenceRecordParameters extends ASiCParameters {

    private static final long serialVersionUID = 7880198032684158062L;

    /** ASiC evidence record manifest file to be added within the container */
    private DSSDocument asicEvidenceRecordManifest;

    /**
     * Default constructor
     */
    public ASiCContainerEvidenceRecordParameters() {
        // empty
    }

    /**
     * Gets ASiCEvidenceRecordManifest file to be added within the container
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getAsicEvidenceRecordManifest() {
        return asicEvidenceRecordManifest;
    }

    /**
     * (Optional) Sets a custom ASiCEvidenceRecordManifest to be added within the container.
     * When defined, the current manifest file will be used for the evidence record incorporation.
     * When not provided, application will create a new ASiCEvidenceRecordManifest based
     * on the objects covered by the evidence record.
     * The filename of the manifest file will be taken from the document name.
     * The filename of the evidence record document will be taken from the manifest signature reference.
     *
     * @param asicEvidenceRecordManifest {@link DSSDocument} representing a valid ASiCEvidenceRecordManifest file
     */
    public void setAsicEvidenceRecordManifest(DSSDocument asicEvidenceRecordManifest) {
        this.asicEvidenceRecordManifest = asicEvidenceRecordManifest;
    }

}
