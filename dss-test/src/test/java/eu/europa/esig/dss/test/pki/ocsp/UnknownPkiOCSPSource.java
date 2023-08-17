package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.dss.pki.model.Revocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.revocation.ocsp.PKIOCSPSource;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.UnknownStatus;

public class UnknownPkiOCSPSource extends PKIOCSPSource {


    public UnknownPkiOCSPSource(CertEntityRepository certEntityRepository) {
        super(certEntityRepository);
    }

    protected void addRevocationStatusToOCSPResponse(BasicOCSPRespBuilder builder, Req r, Revocation revocation) {
        builder.addResponse(r.getCertID(), new UnknownStatus());
    }

}
