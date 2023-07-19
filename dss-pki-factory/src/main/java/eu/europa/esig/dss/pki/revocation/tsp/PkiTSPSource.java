
package eu.europa.esig.dss.pki.revocation.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PkiTSPSource implements TSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PkiTSPSource.class);
    private static final long serialVersionUID = 2327302822894625162L;


    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] bytes) throws DSSException {
        return null;
    }
}
