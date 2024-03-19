package eu.europa.esig.dss.spi.x509.evidencerecord.digest;

import eu.europa.esig.dss.model.Digest;

public interface DataObjectDigestBuilder {

    /**
     * Generates hash value
     *
     * @return {@link Digest} containing the hash value of the data object and the used digest algorithm
     */
    Digest build();

}
