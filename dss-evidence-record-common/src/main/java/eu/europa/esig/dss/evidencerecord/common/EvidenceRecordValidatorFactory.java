package eu.europa.esig.dss.evidencerecord.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface defines the factory to create a {@link EvidenceRecordValidator} for
 * a given {@link DSSDocument}
 */
public interface EvidenceRecordValidatorFactory {

    /**
     * This method tests if the current implementation of {@link EvidenceRecordValidator}
     * supports the given document
     *
     * @param document
     *                 the document to be tested
     * @return true, if the {@link EvidenceRecordValidator} supports the given document
     */
    boolean isSupported(DSSDocument document);

    /**
     * This method instantiates a {@link EvidenceRecordValidator} with the given document
     *
     * @param document
     *                 the document to be used for the {@link EvidenceRecordValidator}
     *                 creation
     * @return an instance of {@link EvidenceRecordValidator} with the document
     */
    EvidenceRecordValidator create(DSSDocument document);

}
