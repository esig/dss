package eu.europa.esig.dss.validation.evidencerecord;

import eu.europa.esig.dss.model.Digest;

/**
 * Generates digest for an evidence record to be embedded within a given signature
 *
 */
public interface SignatureEvidenceRecordDigestBuilder {

    /**
     * Generates hash value for the signature enveloping the evidence-record.
     * Note: the method is not supported for ASiC containers
     *
     * @return {@link Digest} containing the hash value of the binaries and the used digest algorithm
     */
    Digest build();

}
