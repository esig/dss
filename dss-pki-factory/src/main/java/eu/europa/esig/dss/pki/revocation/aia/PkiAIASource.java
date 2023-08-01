package eu.europa.esig.dss.pki.revocation.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class PkiAIASource implements AIASource {

    private boolean completeCertificateChain = false;
    private CertEntityRepository certEntityRepository;


    public PkiAIASource(CertEntityRepository certEntityRepository) {
        this.certEntityRepository = certEntityRepository;
    }

    @Override
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken) {
        Objects.requireNonNull(certificateToken, "CertificateToken shall be provided!");
        CertEntity certEntity = certEntityRepository.getByCertificateToken(certificateToken);
        if (completeCertificateChain) {
            return new HashSet<>(certEntity.getCertificateChain());
        } else if (Utils.isCollectionNotEmpty(certEntity.getCertificateChain())) {
            return Collections.singleton(certEntity.getCertificateChain().get(0));
        } else return new HashSet<>();

    }

    public void setCompleteCertificateChain(boolean completeCertificateChain) {
        this.completeCertificateChain = completeCertificateChain;
    }
}
