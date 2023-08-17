package eu.europa.esig.dss.pki.x509.aia.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class PKIAIASource implements AIASource {

    private static final Logger LOG = LoggerFactory.getLogger(PKIAIASource.class);
    private boolean completeCertificateChain = true;
    private CertEntityRepository certEntityRepository;


    public PKIAIASource(CertEntityRepository certEntityRepository) {
        this.certEntityRepository = certEntityRepository;
    }

    @Override
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken) {

        Objects.requireNonNull(certificateToken, "CertificateToken parameter cannot be null");
        Objects.requireNonNull(certEntityRepository, "CertEntity Repository is not provided");



        CertEntity certEntity = certEntityRepository.getByCertificateToken(certificateToken);
        Objects.requireNonNull(certEntity, "No certification found for the provided CertificateToken.");
        List<CertificateToken> certificateChain = certEntity.getCertificateChain();
        certificateChain.remove(certificateToken);//FIXME

        if (completeCertificateChain) {
            return new HashSet<>(certificateChain);
        } else if (Utils.isCollectionNotEmpty(certificateChain)) {
            CertEntity issuerCertEntity = certEntityRepository.getIssuer(certEntity);
            Objects.requireNonNull(certificateToken, "issuer cannot be null!");
            return new HashSet<>(Set.of(issuerCertEntity.getCertificateToken()));
        } else return new HashSet<>();

    }

    public void setCompleteCertificateChain(boolean completeCertificateChain) {
        this.completeCertificateChain = completeCertificateChain;
    }
}
