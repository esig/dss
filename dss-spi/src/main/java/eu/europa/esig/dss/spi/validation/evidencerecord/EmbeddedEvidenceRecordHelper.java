package eu.europa.esig.dss.spi.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

/**
 * This class contains utility methods required for a processing and validation of an embedded evidence record
 *
 */
public interface EmbeddedEvidenceRecordHelper {

    /**
     * Gets a master signature, enveloping the current evidence record
     *
     * @return {@link AdvancedSignature}
     */
    AdvancedSignature getMasterSignature();

    /**
     * Builds digest for the embedded evidence record for the given {@code DigestAlgorithm}
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @return {@link Digest}
     */
    Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm);

}
