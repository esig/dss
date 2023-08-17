package eu.europa.esig.dss.pki.db;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.business.PostConstructInitializr;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.model.Revocation;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class Db implements CertEntityRepository<DBCertEntity> {
    private static final Logger LOG = LoggerFactory.getLogger(Db.class);
    private static Db instance = null;
    private Map<String, DBCertEntity> map = new HashMap<>();

    private Db() {
    }

    public static Db getInstance() {
        if (instance == null) {
            synchronized (Db.class) {
                instance = new Db();
                PostConstructInitializr.getInstance();
            }
        }
        return instance;
    }

    public void put(String string, DBCertEntity dbCertEntity) {
        map.put(string, dbCertEntity);
    }

    public Map<String, DBCertEntity> getHashMap() {
        return Collections.unmodifiableMap(map);
    }

    @Override
    public List<DBCertEntity> getByParent(DBCertEntity parent) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getParent().equals(parent)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getAll() {
        return new ArrayList<>(map.values());
    }

    @Override
    public DBCertEntity getOneBySerialNumberAndParentSubject(Long serialNumber, String idCA) {
        return getAllBySerialNumberAndParentSubject(serialNumber, idCA).stream().findFirst().orElse(null);
    }

    private List<DBCertEntity> getAllBySerialNumberAndParentSubject(Long serialNumber, String idCA) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getSerialNumber().equals(serialNumber) && dbCertEntity.getParent().getSubject().equals(idCA)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByParentNull() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getParent() == null).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByTrustAnchorTrue() {
        return map.values().stream().filter(DBCertEntity::isTrustAnchor).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByTrustAnchorTrueAndPkiName(String name) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.isTrustAnchor() && dbCertEntity.getPkiName().equals(name)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getByToBeIgnoredTrue() {
        return map.values().stream().filter(DBCertEntity::isToBeIgnored).collect(Collectors.toList());
    }

    @Override
    public List<String> getEndEntityNames() {
        return map.values().stream().filter(dbCertEntity -> !dbCertEntity.isCa() && !dbCertEntity.isOcsp() && !dbCertEntity.isTsa()).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getTsaNames() {
        return map.values().stream().filter(DBCertEntity::isTsa).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getOcspNameList() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<String> getCaNameList() {
        return map.values().stream().map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());

    }

    @Override
    public List<String> getCertNameList() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> getBySubject(String id) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getSubject().equals(id)).collect(Collectors.toList());
    }

    @Override
    public boolean getPss(String id) {
        return map.values().stream().anyMatch(dbCertEntity -> dbCertEntity.getSubject().equals(id));
    }

    @Override
    public DBCertEntity save(DBCertEntity dbCertEntity) {
        if (dbCertEntity.getSubject() != null) {
            this.put(dbCertEntity.getInternalId(), dbCertEntity);
        }
        return dbCertEntity;
    }

    @Override
    public DBCertEntity getCertEntity(String id) {
        List<DBCertEntity> certEntity = this.getBySubject(id);
        if (certEntity == null || certEntity.size() == 0) {
            throw new Error404Exception("Certificate '" + id + "' not found");
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
    public Map<DBCertEntity, Revocation> getRevocationList(DBCertEntity parent) {
        return map.values()
                .stream()
                .filter(dbCertEntity -> dbCertEntity.getRevocationDate() != null)
                .collect(Collectors.toMap(
                        dbCertEntity -> dbCertEntity,
                        dbCertEntity -> new Revocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason()))
                );
    }


    public Revocation getRevocation(DBCertEntity dbCertEntity) {
        if (dbCertEntity.getRevocationDate() != null) {
            return new Revocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason());
        } else return null;
    }
    @Override
    public Revocation getRevocation(CertificateToken certificateToken) {
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
            throw new Error500Exception("Unable to regenerate the certificate");
        }
    }

    @Override
    public DBCertEntity getByCertificateToken(CertificateToken certificateToken) {
        return getOneBySerialNumberAndParentSubject(certificateToken.getSerialNumber().longValue(), DSSASN1Utils.extractAttributeFromX500Principal(BCStyle.CN, certificateToken.getIssuer()));
    }
}
