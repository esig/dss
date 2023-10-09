package eu.europa.esig.dss.pki.x509.revocation.ocsp;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.utils.Utils;

import java.util.Map;

/**
 * The PkiOCSPSource class implements the OCSPSource interface for obtaining revocation tokens.
 * It retrieves OCSP responses for a given certificate by sending OCSP requests to a specified OCSP responder.
 *
 */
public class PKIDelegatedOCSPSource extends PKIOCSPSource {

    private static final long serialVersionUID = 1812419786179539363L;

    /** Map of CA cert entities and their delegated OCSP Responders */
    private Map<CertEntity, CertEntity> ocspResponders;

    /**
     * Default constructor
     *
     * @param certEntityRepository {@link CertEntityRepository}
     */
    public PKIDelegatedOCSPSource(final CertEntityRepository certEntityRepository) {
        super(certEntityRepository);
    }

    /**
     * Sets a map of CA cert entities and their delegated OCSP Responders
     *
     * @param ocspResponders a map between CA {@link CertEntity}s and delegated OCSP Responder {@link CertEntity}s
     */
    public void setOcspResponders(Map<CertEntity, CertEntity> ocspResponders) {
        this.ocspResponders = ocspResponders;
    }

    @Override
    public void setOcspResponder(CertEntity ocspResponder) {
        throw new UnsupportedOperationException("Method #setOcspResponder is not supported " +
                "within PKIDelegatedOCSPSource class. Use #setOcspResponders method instead.");
    }

    @Override
    protected CertEntity getOCSPResponder(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        CertEntity issuerCertEntity = certEntityRepository.getByCertificateToken(issuerCertificateToken);
        if (Utils.isMapNotEmpty(ocspResponders)) {
            CertEntity ocspResponder = ocspResponders.get(issuerCertEntity);
            if (ocspResponder != null) {
                return ocspResponder;
            }
        }
        return issuerCertEntity;
    }

}
