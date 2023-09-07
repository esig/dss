package eu.europa.esig.dss.pki.jaxb.db;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.jaxb.model.DBCertEntity;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


public class JaxbCertEntityRepository implements CertEntityRepository<DBCertEntity> {
    private static final Logger LOG = LoggerFactory.getLogger(JaxbCertEntityRepository.class);

    private final Set<DBCertEntity> certEntities = new HashSet<>();

    public JaxbCertEntityRepository() {
    }


    private void put(DBCertEntity dbCertEntity) {
        certEntities.add(dbCertEntity);
    }

    public Set<DBCertEntity> getCertificationEntities() {
        return Collections.unmodifiableSet(certEntities);
    }

    @Override
    public List<DBCertEntity> getByParent(DBCertEntity parent) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getParent().equals(parent)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getAll() {
        return new ArrayList<>(certEntities);
    }

    @Override
    public DBCertEntity getOneBySerialNumberAndParentSubject(Long serialNumber, String idCA) {
        return getAllBySerialNumberAndParentSubject(serialNumber, idCA).stream().findFirst().orElse(null);
    }

    private List<DBCertEntity> getAllBySerialNumberAndParentSubject(Long serialNumber, String idCA) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getSerialNumber().equals(serialNumber) && dbCertEntity.getParent().getSubject().equals(idCA)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByParentNull() {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getParent() == null).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getTrustAnchors() {
        return certEntities.stream().filter(DBCertEntity::isTrustAnchor).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getTrustAnchorsByPkiName(String name) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.isTrustAnchor() && dbCertEntity.getPkiName().equals(name)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByToBeIgnoredTrue() {
        return certEntities.stream().filter(DBCertEntity::isToBeIgnored).collect(Collectors.toList());
    }

    @Override
    public List<String> getEndEntityNames() {
        return certEntities.stream().filter(dbCertEntity -> !dbCertEntity.isCa() && !dbCertEntity.isOcsp() && !dbCertEntity.isTsa()).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getTsaNames() {
        return certEntities.stream().filter(DBCertEntity::isTsa).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getOcspNameList() {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getCaNameList() {
        return certEntities.stream().map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getCertNameList() {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getBySubject(String id) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getSubject().equals(id)).collect(Collectors.toList());
    }

    @Override
    public boolean getPss(String id) {
        return certEntities.stream().anyMatch(dbCertEntity -> dbCertEntity.getSubject().equals(id));
    }

    @Override
    public DBCertEntity save(DBCertEntity dbCertEntity) {
        if (dbCertEntity.getSubject() != null) {
            this.put(dbCertEntity);
        }
        return dbCertEntity;
    }

    @Override
    public DBCertEntity getCertEntityBySubject(String subjectName) {
        List<DBCertEntity> certEntity = this.getBySubject(subjectName);
        if (certEntity == null || certEntity.size() == 0) {
            LOG.warn("Certificate '" + subjectName + "' not found");
            return null;
        }
        if (certEntity.size() > 1) {
            LOG.warn("More than one result (returns first)");
        }
        return certEntity.get(0);
    }

    @Override
    public X509CertificateHolder convertToX509CertificateHolder(DBCertEntity certEntity) {
        return convertToX509CertificateHolder(certEntity.getCertificateToken().getEncoded());
    }

    @Override
    public X509CertificateHolder[] getCertificateChain(DBCertEntity certEntity) {
        List<X509CertificateHolder> certChain = new ArrayList<>();
        DBCertEntity entity = certEntity;
        while (entity != null) {
            certChain.add(convertToX509CertificateHolder(entity));
            DBCertEntity parent = entity.getParent();
            if (entity.getInternalId().equals(parent.getInternalId())) {
                break;
            }
            entity = parent;
        }
        return certChain.toArray(new X509CertificateHolder[certChain.size()]);
    }


    @Override
    public Map<DBCertEntity, CertEntityRevocation> getRevocationList(DBCertEntity parent) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getRevocationDate() != null && parent.equals(dbCertEntity.getParent())).collect(Collectors.toMap(dbCertEntity -> dbCertEntity, dbCertEntity -> new CertEntityRevocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason())));
    }


    public CertEntityRevocation getRevocation(DBCertEntity dbCertEntity) {
        if (dbCertEntity.getRevocationDate() != null) {
            return new CertEntityRevocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason());
        } else return null;
    }

    @Override
    public CertEntityRevocation getRevocation(CertificateToken certificateToken) {
        return getRevocation(getByCertificateToken(certificateToken));
    }

    @Override
    public CertEntity getIssuer(DBCertEntity certEntity) {
        return certEntity.getParent();
    }

    private X509CertificateHolder convertToX509CertificateHolder(byte[] binary) {
        try {
            return new X509CertificateHolder(binary);
        } catch (IOException e) {
            LOG.error("Unable to regenerate the certificate", e);
            throw new DSSException("Unable to regenerate the certificate");
        }
    }

    @Override
    public DBCertEntity getByCertificateToken(CertificateToken certificateToken) {
        return getOneBySerialNumberAndParentSubject(certificateToken.getSerialNumber().longValue(), DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, certificateToken.getIssuer()));
    }
}
