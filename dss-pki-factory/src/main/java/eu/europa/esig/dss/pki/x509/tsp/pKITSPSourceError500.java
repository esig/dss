package eu.europa.esig.dss.pki.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class pKITSPSourceError500 implements TSPSource {
    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
          throw new Error500Exception("Something wrong happened");
    }


}
