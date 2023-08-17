package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.pki.manifest.RevocationReason;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.model.Revocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.pki.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.pki.utils.PKIUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.UnknownStatus;

import java.util.Date;
import java.util.Map;

public class UnknownPkiCRLSource extends PKICRLSource {


    public UnknownPkiCRLSource(CertEntityRepository certEntityRepository) {
        super(certEntityRepository);
        super.setNextUpdate(new Date());
    }

    protected void addRevocationsToCRL(X509v2CRLBuilder builder, Map<DBCertEntity, Revocation> revocationList) {
        revocationList.forEach((key, value) -> {
            X509CertificateHolder entry = DSSASN1Utils.getX509CertificateHolder(key.getCertificateToken());
            builder.addCRLEntry(entry.getSerialNumber(), value.getRevocationDate(), PKIUtils.getCRLReason(RevocationReason.UNKNOWN));
        });
    }


}
