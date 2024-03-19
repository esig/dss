package eu.europa.esig.dss.spi.x509.evidencerecord.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Creates an instance of {@code eu.europa.esig.dss.spi.x509.evidencerecord.DataObjectDigestBuilder}
 *
 */
public interface DataObjectDigestBuilderFactory {

    /**
     * Creates an instance of {@code DataObjectDigestBuilder} to build hash for the {@code document},
     * according to the given implementation, using a default digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash for
     * @return {@link DataObjectDigestBuilder}
     */
    DataObjectDigestBuilder create(DSSDocument document);

    /**
     * Creates an instance of {@code DataObjectDigestBuilder} to build hash for the {@code document},
     * according to the given implementation, using a provided {@code digestAlgorithm}
     *
     * @param document {@link DSSDocument} to compute hash for
     * @param digestAlgorithm {@link DigestAlgorithm} to use
     * @return {@link DataObjectDigestBuilder}
     */
    DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm);

}
