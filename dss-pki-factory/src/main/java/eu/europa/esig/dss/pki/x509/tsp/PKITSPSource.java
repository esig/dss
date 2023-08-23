package eu.europa.esig.dss.pki.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;

import java.util.Objects;

/**
 * A class that represents a PKI Time Stamp Protocol (TSP) source extending the KeyEntityTSPSource.
 * It provides functionality to generate time-stamp responses for given digest algorithms and digests.
 */
public class PKITSPSource extends KeyEntityTSPSource {

    /**
     * Constructs a new PkiTSPSource instance with the specified certificate entity.
     *
     * @param certEntity The certificate entity associated with the TSP source.
     */
    public PKITSPSource(CertEntity certEntity) {
        super(certEntity.getPrivateKeyObject(), certEntity.getCertificateToken(), certEntity.getCertificateChain());
    }

    /**
     * Retrieves a time-stamp response for the given digest algorithm and digest.
     *
     * @param digestAlgorithm The digest algorithm to be used for generating the time-stamp response.
     * @param digest          The digest for which the time-stamp response is to be generated.
     * @return A TimestampBinary object representing the time-stamp response in binary format.
     * @throws DSSException If the given digest algorithm is not supported or if there is an issue generating the time-stamp response.
     */
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm is not defined!");
        Objects.requireNonNull(digest, "digest is not defined!");

        if (!acceptedDigestAlgorithms.contains(digestAlgorithm)) {
            throw new DSSException(String.format(
                    "DigestAlgorithm '%s' is not supported by the PkiTSPSource implementation!", digestAlgorithm));
        }
        return super.getTimeStampResponse(digestAlgorithm, digest);
    }

}
