package eu.europa.esig.dss.pki.service;

import eu.europa.esig.pki.manifest.DigestAlgo;
import eu.europa.esig.pki.manifest.RevocationReason;
import eu.europa.esig.dss.pki.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class CertificateEntityService {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateEntityService.class);

    private static final JcaX509CertificateConverter CONVERTER;
    private static CertEntityRepository<DBCertEntity> repository;
    private static CertificateEntityService certificateEntityService;

    private CertificateEntityService() {

    }

    public static CertificateEntityService getInstance() {
        if (certificateEntityService == null) {
            synchronized (CertificateEntityService.class) {
                repository = JaxbCertEntityRepository.getInstance();
                certificateEntityService = new CertificateEntityService();
            }
        }
        return certificateEntityService;
    }

    static {
        CONVERTER = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
    }


    public List<X509CertificateHolder> getTrustAnchors() {
        List<DBCertEntity> trustAnchorEntities = repository.getByTrustAnchorTrue();
        return getCertificates(trustAnchorEntities);
    }


    private List<X509CertificateHolder> getCertificates(List<DBCertEntity> entities) {
        List<X509CertificateHolder> result = new ArrayList<>();
        for (DBCertEntity certEntity : entities) {
            result.add(DSSASN1Utils.getX509CertificateHolder((certEntity.getCertificateToken())));
        }
        return result;
    }

    public X509CertificateHolder getCertificate(String id) {
        DBCertEntity entity = getEntity(id);
        return DSSASN1Utils.getX509CertificateHolder(entity.getCertificateToken());
    }


    public X509CertificateHolder[] getCertificateChain(String id) {
        DBCertEntity certEntity = getEntity(id);
        return getCertificateChain(certEntity);
    }


    public X509CertificateHolder[] getCertificateChain(DBCertEntity certEntity) {
        List<X509CertificateHolder> certChain = new ArrayList<>();
        DBCertEntity entity = certEntity;
        while (entity != null) {
            certChain.add(DSSASN1Utils.getX509CertificateHolder(entity.getCertificateToken()));
            DBCertEntity parent = entity.getParent();
            if (entity.getInternalId().equals(parent.getInternalId())) {
                break;
            }
            entity = parent;
        }
        return certChain.toArray(new X509CertificateHolder[certChain.size()]);
    }


    public PrivateKey getPrivateKey(String id) {
        DBCertEntity entity = getEntity(id);
        return getPrivateKey(entity);
    }


    public DBCertEntity getCertificateEntity(String id) {
        return this.getEntity(id);
    }

    private DBCertEntity getEntity(String id) {
        List<DBCertEntity> certEntity = repository.getBySubject(id);
        if (certEntity == null || certEntity.size() == 0) {
            throw new Error404Exception("Certificate '" + id + "' not found");
        }
        if (certEntity.size() > 1) {
            LOG.warn("More than one result (returns first)");
        }
        return certEntity.get(0);
    }


    public PrivateKey getPrivateKey(DBCertEntity certEntity) {
        return getPrivateKey(certEntity.getPrivateKey(), certEntity.getPrivateKeyAlgo());
    }

    private PrivateKey getPrivateKey(byte[] privateKeyBytes, String algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (GeneralSecurityException e) {
            LOG.error("Unable to regenerate the private key", e);
            throw new Error500Exception("Unable to regenerate the private key");
        }
    }


    public String getCommonName(X509CertificateHolder cert) {
        return cert.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    public Certificate convert(X509CertificateHolder x509CertificateHolder) throws CertificateException {
        return CONVERTER.getCertificate(x509CertificateHolder);
    }


}
