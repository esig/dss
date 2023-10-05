package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.UnknownStatus;

public class UnknownPkiOCSPSource extends PKIOCSPSource {

    private static final long serialVersionUID = -2941608469469755568L;

    public UnknownPkiOCSPSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        super(certEntityRepository);
    }

    @Override
    protected void addRevocationStatusToOCSPResponse(BasicOCSPRespBuilder builder, OCSPReq ocspReq, CertEntityRevocation certEntityRevocation) {
        Req r = ocspReq.getRequestList()[0];
        builder.addResponse(r.getCertID(), new UnknownStatus());
    }

}
