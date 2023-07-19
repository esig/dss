package eu.europa.esig.dss.pki.repository;

import eu.europa.esig.dss.pki.model.DBCertEntity;


import java.util.List;

public interface CertEntityRepository {

    List<DBCertEntity> findByParent(DBCertEntity parent);

    List<DBCertEntity> findAll();

    DBCertEntity findBySerialNumberAndParentSubject(Long serialNumber, String idCA);

    List<DBCertEntity> findByParentNull();

    List<DBCertEntity> findByTrustAnchorTrue();

    List<DBCertEntity> findByTrustAnchorTrueAndPkiName(String name);

    List<DBCertEntity> findByToBeIgnoredTrue();

    //    @Query("select distinct(e.subject) from DBCertEntity e where e.ca = false and e.ocsp = false and e.tsa = false")
    List<String> getEndEntityNames();

    //    @Query("select distinct(e.subject) from DBCertEntity e where e.tsa = true")
    List<String> getTsaNames();

    //    @Query("select distinct(e.subject)from DBCertEntity e where e.ocspResponder is not null")
    List<String> getOcspNameList();

    //    @Query("select distinct(e.subject) from DBCertEntity e where e.ca = true")
    List<String> getCaNameList();

    //    @Query("select distinct( e.subject) from DBCertEntity e")
    List<String> getCertNameList();

    List<DBCertEntity> findBySubject(String id);

    //    @Query("select e.pss from DBCertEntity e where e.subject = ?1")
    boolean getPss(String id);

    DBCertEntity save(DBCertEntity dbCertEntity);

    DBCertEntity getByCrlUrl(String crlUrl);

}
