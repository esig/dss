package eu.europa.esig.dss.test.pki.tsp;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;

import java.math.BigInteger;
import java.util.Date;

/**
 * A class that represents a PKI Time Stamp Protocol (TSP) source extending the KeyEntityTSPSource.
 * It provides functionality to generate time-stamp responses for given digest algorithms and digests.
 */
public class PkiTSPFailSource extends PKITSPSource {

    /**
     * Constructs a new PkiTSPSource instance with the specified certificate entity.
     *
     * @param certEntity The certificate entity associated with the TSP source.
     */
    public PkiTSPFailSource(CertEntity certEntity) {
        super(certEntity);
    }

    @Override
    protected TimeStampResponse buildResponse(TimeStampResponseGenerator responseGenerator, TimeStampRequest request,
                                              BigInteger timeStampSerialNumber, Date productionTime) throws TSPException {
        return responseGenerator.generateFailResponse(PKIStatus.REJECTION, PKIFailureInfo.systemFailure, "Error for testing");
    }

}
