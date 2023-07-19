package eu.europa.esig.dss.pki.db;

import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;

import java.util.*;
import java.util.stream.Collectors;

public class Db implements CertEntityRepository {
    private static Db instance = null;
    private Map<String, DBCertEntity> map = new HashMap<>();

    private Db() {
    }

    public static Db getInstance() {
        if (instance == null) {
            synchronized (Db.class) {
                instance = new Db();
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
    public List<DBCertEntity> findByParent(DBCertEntity parent) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getParent().equals(parent)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> findAll() {
        return new ArrayList<>(map.values());
    }

    @Override
    public DBCertEntity findBySerialNumberAndParentSubject(Long serialNumber, String idCA) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getSerialNumber().equals(serialNumber) && dbCertEntity.getParent().getSubject().equals(idCA)).findFirst().orElse(null);
    }

    @Override
    public List<DBCertEntity> findByParentNull() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getParent() == null).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> findByTrustAnchorTrue() {
        return map.values().stream().filter(DBCertEntity::isTrustAnchor).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> findByTrustAnchorTrueAndPkiName(String name) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.isTrustAnchor() && dbCertEntity.getPkiName().equals(name)).collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> findByToBeIgnoredTrue() {
        return map.values().stream().filter(DBCertEntity::isToBeIgnored).collect(Collectors.toList());
    }

    //select distinct(e.subject) from DBCertEntity e where e.ca = false and e.ocsp = false and e.tsa = false
    @Override
    public List<String> getEndEntityNames() {
        return map.values().stream().filter(dbCertEntity -> !dbCertEntity.isCa() && !dbCertEntity.isOcsp() && !dbCertEntity.isTsa()).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    //select distinct(e.subject) from DBCertEntity e where e.tsa = true")
    @Override
    public List<String> getTsaNames() {
        return map.values().stream().filter(DBCertEntity::isTsa).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    //"select distinct(e.subject)from DBCertEntity e where e.ocspResponder is not null")
    @Override
    public List<String> getOcspNameList() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    //select distinct( e.subject) from DBCertEntity e
    @Override
    public List<String> getCaNameList() {
        return map.values().stream().map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());

    }

    @Override
    public List<String> getCertNameList() {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null).map(DBCertEntity::getSubject).distinct().collect(Collectors.toList());
    }

    @Override
    public List<DBCertEntity> findBySubject(String id) {
        return map.values().stream().filter(dbCertEntity -> dbCertEntity.getSubject().equals(id)).collect(Collectors.toList());
    }

    @Override
    public boolean getPss(String id) {
        return map.values().stream().anyMatch(dbCertEntity -> dbCertEntity.getSubject().equals(id));
    }

    public DBCertEntity getByCrlUrl(String crlUrl) {
        return map.get(crlUrl);
    }

    @Override
    public DBCertEntity save(DBCertEntity dbCertEntity) {
        if (dbCertEntity.getSubject() != null) {
            this.put(dbCertEntity.getInternalId(), dbCertEntity);
        }
        return dbCertEntity;
    }

}
