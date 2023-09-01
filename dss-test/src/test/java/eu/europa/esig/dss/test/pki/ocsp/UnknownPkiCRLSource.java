package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.util.Date;
import java.util.Map;

public class UnknownPkiCRLSource extends PKICRLSource {


    public UnknownPkiCRLSource(CertEntityRepository certEntityRepository) {
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
