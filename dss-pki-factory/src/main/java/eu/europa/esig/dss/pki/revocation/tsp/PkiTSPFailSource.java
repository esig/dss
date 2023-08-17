package eu.europa.esig.dss.pki.revocation.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A class that represents a PKI Time Stamp Protocol (TSP) source extending the KeyEntityTSPSource.
 * It provides functionality to generate time-stamp responses for given digest algorithms and digests.
 */
public class PkiTSPFailSource extends KeyEntityTSPSource {
    /**
     * The certificate entity associated with the TSP source.
     */
    private CertEntity certEntity;

    /**
     * Constructs a new PkiTSPSource instance with the specified certificate entity.
     *
     * @param certEntity The certificate entity associated with the TSP source.
     */
    public PkiTSPFailSource(CertEntity certEntity) {
        super();
        this.certEntity = certEntity;
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

        try {
            TimeStampResponseGenerator responseGenerator = initResponseGenerator(certEntity.getPrivateKeyObject(),
                    certEntity.getCertificateToken().getCertificate(),
                    certEntity.getCertificateChain().stream().map(CertificateToken::getCertificate).collect(Collectors.toList()),
                    getASN1ObjectIdentifier(digestAlgorithm));

            TimeStampResponse response = generateFailedResponse(responseGenerator);
            return new TimestampBinary(response.getTimeStampToken().getEncoded());

        } catch (IOException | TSPException e) {
            throw new DSSException(String.format("Unable to generate a timestamp. Reason : %s", e.getMessage()), e);
        }
    }


    /**
     * Sets the certificate entity associated with the TSP source.
     *
     * @param certEntity The certificate entity to be set for the TSP source.
     */
    public void setCertEntity(CertEntity certEntity) {
        this.certEntity = certEntity;
    }

    private TimeStampResponse generateFailedResponse(TimeStampResponseGenerator gen) throws TSPException {
        return gen.generateFailResponse(PKIStatus.REJECTION, PKIFailureInfo.systemFailure, "Error for testing");
    }

}
