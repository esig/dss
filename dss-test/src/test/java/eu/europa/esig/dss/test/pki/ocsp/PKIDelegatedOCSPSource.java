package eu.europa.esig.dss.test.pki.ocsp;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.model.DBCertEntity;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * The PkiOCSPSource class implements the OCSPSource interface for obtaining revocation tokens.
 * It retrieves OCSP responses for a given certificate by sending OCSP requests to a specified OCSP responder.
 */
public class PKIDelegatedOCSPSource extends PKIOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PKIDelegatedOCSPSource.class);
    private Map<CertificateToken, CertEntity> ocspResponders;


    public PKIDelegatedOCSPSource(CertEntityRepository certEntityRepository) {
        super(certEntityRepository);
        ocspResponders = (Map<CertificateToken, CertEntity>) certEntityRepository.getAll()
                .stream().filter(dbCertEntity -> ((DBCertEntity) dbCertEntity).getOcspResponder() != null)
                .collect(Collectors.toMap(DBCertEntity::getCertificateToken, DBCertEntity::getOcspResponder));
    }

    @Override
    protected CertEntity getCertEntity(CertificateToken issuerCertificateToken) {
        CertEntity currentCertEntity;
        if (!ocspResponders.containsKey(issuerCertificateToken)) {
            currentCertEntity = super.getCertEntityRepository().getByCertificateToken(issuerCertificateToken);
        } else {
            currentCertEntity = ocspResponders.get(issuerCertificateToken);
        }
        return currentCertEntity;
    }
}
