package eu.europa.esig.dss.test.pki.crl;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.util.Date;
import java.util.Map;

public class UnknownPkiCRLSource extends PKICRLSource {

    private static final long serialVersionUID = 6793262225588156549L;

    public UnknownPkiCRLSource(CertEntityRepository<? extends CertEntity> certEntityRepository) {
        super(certEntityRepository);
        super.setNextUpdate(new Date());
    }

    protected void addRevocationsToCRL(X509v2CRLBuilder builder, Map<CertEntity, CertEntityRevocation> revocationList) {
        revocationList.forEach((key, value) -> {
            X509CertificateHolder entry = DSSASN1Utils.getX509CertificateHolder(key.getCertificateToken());
            builder.addCRLEntry(entry.getSerialNumber(), value.getRevocationDate(), CRLReason.unspecified);
        });
    }

}
