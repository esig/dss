package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.*;
import eu.europa.esig.dss.pki.constant.LoadProperties;
import eu.europa.esig.dss.pki.db.Db;
import eu.europa.esig.dss.pki.dto.CertSubjectWrapperDTO;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.wrapper.CertificateWrapper;
import eu.europa.esig.dss.pki.wrapper.EntityId;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class Initializr {

    private static final Logger LOG = LoggerFactory.getLogger(Initializr.class);

    private static final String CUSTOM_URL_PREFIX = "custom/";
    private static final String EXTENDED_URL_PREFIX = "extended/";
    private static final String EMPTY_URL_PREFIX = "";
    private static final String CRL_EXTENSION = ".crl";
    private static final String CRL_PATH = "crl/";
    private static final String CRT_EXTENSION = ".crt";
    private static final String CRT_PATH = "crt/";
    private static final String OCSP_PATH = "ocsp/";
    private static final String PKI_FACTORY_HOST = "pki.factory.host";
    private static final String PKI_FACTORY_COUNTRY = "pki.factory.country";
    private static final String PKI_FACTORY_ORGANISATION = "pki.factory.organisation";
    private static final String PKI_FACTORY_ORGANISATION_UNIT = "pki.factory.organisation.unit";

    private final String host = LoadProperties.getValue(PKI_FACTORY_HOST);

    private final String country = LoadProperties.getValue(PKI_FACTORY_COUNTRY, "CC");

    private final String organisation = LoadProperties.getValue(PKI_FACTORY_ORGANISATION, "Organization");

    private final String organisationUnit = LoadProperties.getValue(PKI_FACTORY_ORGANISATION_UNIT, "CERT FOR TEST");

    private static PkiMarshallerService pkiMarshallerService;

    private static CertificateEntityService entityService;

    private static Initializr initializr;

    public static Initializr getInstance() {
        if (initializr == null) {
            synchronized (Db.class) {
                entityService = CertificateEntityService.getInstance();
                pkiMarshallerService = PkiMarshallerService.getInstance();
                initializr = new Initializr();
            }
        }
        return initializr;
    }

    private Initializr() {

    }

    /**
     * Initializes the certificate entities and their related information using the provided PKIs.
     *
     * @throws Exception if an error occurs during initialization.
     */
    public void init() throws Exception {

        Map<EntityId, X500Name> x500names = new HashMap<>();
        Map<String, KeyPair> keyPairs = new HashMap<>();
        Map<EntityId, DBCertEntity> entities = new HashMap<>();

        Collection<Pki> pkis = pkiMarshallerService.getPKIs();

        for (Pki pki : pkis) {
            LOG.info("PKI {} : {} certificates", pki.getName(), pki.getCertificate().size());

            for (CertificateType certType : pki.getCertificate()) {

                LOG.info("Init '{}' ...", certType.getSubject());

                DBCertEntity issuer = getIssuer(entities, certType.getIssuer());
                String issuerName = issuer != null ? issuer.getSubject() : certType.getSubject();
                CertificateWrapper wrapper = new CertificateWrapper(certType, issuerName);

                KeyPair subjectKeyPair = getKeyPair(keyPairs, wrapper.getSubject(), wrapper.getKeyAlgo());
                KeyPair issuerKeyPair;
                if (wrapper.isSelfSigned()) {
                    issuerKeyPair = subjectKeyPair;
                } else {
                    issuerKeyPair = getKeyPair(keyPairs, getIssuerSubject(entities, wrapper.getIssuer()), wrapper.getKeyAlgo());
                }

                X500Name subjectX500Name = getX500NameSubject(x500names, wrapper, new CertSubjectWrapperDTO(certType, pki.getCountry(), pki.getOrganization()));
                X500Name issuerX500Name = getX500NameIssuer(x500names, wrapper.getIssuer());

                X509CertBuilder certBuilder = new X509CertBuilder();
                certBuilder.subject(subjectX500Name, subjectKeyPair.getPublic());
                certBuilder.issuer(issuerX500Name, issuerKeyPair.getPrivate());

                certBuilder.digestAlgo(wrapper.getDigestAlgo());

                certBuilder.aia(getAiaUrl(wrapper.getAIA()));
                String urlCrl = getCrlUrl(wrapper.getCRL());
                certBuilder.crl(urlCrl);
                certBuilder.ocsp(getOcspUrl(wrapper.getOCSP()));

                certBuilder.keyUsage(wrapper.getKeyUsage());
                certBuilder.certificatePolicies(wrapper.getCertificatePolicies());
                certBuilder.qcStatementIds(wrapper.getQCStatementsIds());

                if (wrapper.isCA()) {
                    certBuilder.ca();
                }
                if (wrapper.isTSA()) {
                    certBuilder.timestamping();
                }
                if (wrapper.isOcspNoCheck()) {
                    certBuilder.ocspNoCheck();
                }
                if (wrapper.isOcspSigning()) {
                    certBuilder.ocspSigningExtension();
                }

                certBuilder.pss(wrapper.isPSS());
                X509CertificateHolder certificateHolder = certBuilder.build(BigInteger.valueOf(wrapper.getSerialNumber()), wrapper.getNotBefore(), wrapper.getNotAfter());

                EntityId key = wrapper.getKey();
                boolean selfSign = wrapper.getIssuer().equals(key);

                DBCertEntity entity = entityService.persist(certificateHolder, subjectKeyPair.getPrivate(), wrapper.getRevocationDate(), wrapper.getRevocationReason(), wrapper.isSuspended(), getEntity(entities, wrapper.getIssuer(), selfSign), getEntity(entities, wrapper.getOCSPResponder(), false), wrapper.isTrustAnchor(), wrapper.isCA(), wrapper.isTSA(), wrapper.isOcspSigning(), wrapper.isToBeIgnored(), pki.getName(), wrapper.isPSS(), wrapper.getDigestAlgo());

                saveEntity(entities, key, entity);

                LOG.info("Creation of '{}' : DONE", certType.getSubject());
            }
        }
    }

    /**
     * Retrieves the issuer certificate entity with the given entity key from the entities map.
     *
     * @param entities The map of certificate entities, where the key is the EntityId and the value is the DBCertEntity.
     * @param entityKey The entity key for the issuer certificate.
     * @return The issuer certificate entity associated with the given entity key, or null if not found.
     */
    private DBCertEntity getIssuer(Map<EntityId, DBCertEntity> entities, EntityKey entityKey) {
        if (entityKey.getSerialNumber() != null) {
            return entities.get(new EntityId(entityKey));
        }
        return null;
    }
    /**
     * Retrieves the subject name of the certificate entity associated with the given EntityId from the entities map.
     *
     * @param entities The map of certificate entities, where the key is the EntityId and the value is the DBCertEntity.
     * @param key The EntityId for the certificate entity.
     * @return The subject name of the certificate entity associated with the given EntityId.
     * @throws IllegalArgumentException if the certificate entity is not found in the entities map.
     */
    private String getIssuerSubject(Map<EntityId, DBCertEntity> entities, EntityId key) {
        DBCertEntity entity = entities.get(key);
        if (entity == null) {
            throw new IllegalArgumentException("Entity not found " + key);
        }
        return entity.getSubject();
    }

    private DBCertEntity getEntity(Map<EntityId, DBCertEntity> entities, EntityId key, boolean ignoreException) {
        if (key != null) {
            DBCertEntity certEntity = entities.get(key);
            if (certEntity == null && !ignoreException) {
                throw new IllegalArgumentException("Entity not found " + key);
            }
            return certEntity;
        }
        return null;
    }

    public String getCrlUrl(CRLType crlEntity) {
        if (crlEntity != null && crlEntity.getValue() != null) {
            if (crlEntity.getDate() == null) {
                return host + CRL_PATH + getCertStringUrl(crlEntity, EXTENDED_URL_PREFIX) + CRL_EXTENSION;
            } else {
                Date time = crlEntity.getDate().toGregorianCalendar().getTime();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd-hh-mm");
                String date = sdf.format(time);
                if (crlEntity.isFutur() == null) {
                    return host + CRL_PATH + date + "/" + crlEntity.getValue() + CRL_EXTENSION;
                } else {
                    return host + CRL_PATH + date + "/" + crlEntity.isFutur() + "/" + crlEntity.getValue() + CRL_EXTENSION;
                }
            }
        }
        return null;
    }

    private String getOcspUrl(EntityKey entityKey) {
        if (entityKey != null) {
            return host + OCSP_PATH + getCertStringUrl(entityKey, CUSTOM_URL_PREFIX);
        }
        return null;
    }

    private String getAiaUrl(EntityKey entityKey) {
        if (entityKey != null) {
            return host + CRT_PATH + getCertStringUrl(entityKey, EMPTY_URL_PREFIX) + CRT_EXTENSION;
        }
        return null;
    }

    private String getCertStringUrl(EntityKey entityKey, String urlPrefix) {
        return entityKey.getSerialNumber() != null ? urlPrefix + entityKey.getValue() + "/" + entityKey.getSerialNumber() : entityKey.getValue();
    }

    /**
     * Get issuer from x500names map
     *
     * @param x500names
     * @param key
     * @throws IllegalStateException X500Name not found in map for given key
     */
    private X500Name getX500NameIssuer(Map<EntityId, X500Name> x500names, EntityId key) {
        if (x500names.containsKey(key)) {
            return x500names.get(key);
        }
        throw new IllegalStateException("EntityId not found : " + key);
    }

    /**
     * Initialize subject based on given subject/organization (optional.)/country (optional.)
     *
     * @param x500Names          a map between {@link EntityId} and {@link X500Name}
     * @param certificateWrapper {@link CertificateWrapper}
     * @param subjectWrapper     {@link CertSubjectWrapperDTO}
     * @throws IllegalStateException Common name is null
     */
    private X500Name getX500NameSubject(Map<EntityId, X500Name> x500Names, CertificateWrapper certificateWrapper, CertSubjectWrapperDTO subjectWrapper) {
        EntityId key = certificateWrapper.getKey();
        if (x500Names.containsKey(key)) {
            return x500Names.get(key);
        } else {
            if (subjectWrapper.getCommonName() == null) {
                throw new IllegalStateException("Missing common name for " + key);
            }

            String tmpCountry;
            if (!Utils.isStringEmpty(subjectWrapper.getCountry())) {
                tmpCountry = subjectWrapper.getCountry();
            } else {
                tmpCountry = country;
            }

            String tmpOrganisation;
            if (!Utils.isStringEmpty(subjectWrapper.getOrganization())) {
                tmpOrganisation = subjectWrapper.getOrganization();
            } else {
                tmpOrganisation = organisation;
            }

            X500Name x500Name = new X500NameBuilder().commonName(subjectWrapper.getCommonName()).pseudo(subjectWrapper.getPseudo()).country(tmpCountry).organisation(tmpOrganisation).organisationUnit(organisationUnit).build();
            x500Names.put(key, x500Name);
            x500Names.put(new EntityId(certificateWrapper.getSubject(), null), x500Name);
            return x500Name;
        }
    }

    private KeyPair getKeyPair(Map<String, KeyPair> keyPairs, String subject, KeyAlgo algo) throws GeneralSecurityException {
        if (keyPairs.containsKey(subject)) {
            return keyPairs.get(subject);
        } else {
            KeyPair keyPair = KeyPairBuilder.build(algo);
            keyPairs.put(subject, keyPair);
            return keyPair;
        }
    }

    private void saveEntity(Map<EntityId, DBCertEntity> entities, EntityId key, DBCertEntity entity) {
        entities.put(key, entity);
        entities.put(new EntityId(entity.getSubject(), null), entity);
    }

}
