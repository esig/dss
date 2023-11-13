/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.builder.JAXBCertEntityBuilder;
import eu.europa.esig.dss.pki.jaxb.builder.KeyPairBuilder;
import eu.europa.esig.dss.pki.jaxb.builder.X500NameBuilder;
import eu.europa.esig.dss.pki.jaxb.builder.X509CertificateBuilder;
import eu.europa.esig.dss.pki.jaxb.model.EntityId;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.CERT_EXTENSION;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.CERT_PATH;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.CRL_EXTENSION;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.CRL_PATH;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.OCSP_EXTENSION;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.OCSP_PATH;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.PKI_FACTORY_COUNTRY;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.PKI_FACTORY_HOST;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.PKI_FACTORY_ORGANISATION;
import static eu.europa.esig.dss.pki.jaxb.property.PKIJaxbProperties.PKI_FACTORY_ORGANISATION_UNIT;


/**
 * Builds {@code JAXBCertEntity} objects from the provided XML PKI configuration and stores the result in {@code JAXBCertEntityRepository}
 *
 */
public class JAXBPKILoader {

    private static final Logger LOG = LoggerFactory.getLogger(JAXBPKILoader.class);

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    /**
     * Default constructor
     */
    public JAXBPKILoader() {
        // empty
    }

    /**
     * Generates certificate entries from configuration provided within {@code pkiFile} and populates the {@code repository}
     *
     * @param repository {@link JAXBCertEntityRepository} to be populated
     * @param pkiFile {@link File} containing PKI configuration
     */
    public void persistPKI(JAXBCertEntityRepository repository, File pkiFile) {
        try {
            persistPKI(repository, PKIJaxbFacade.newFacade().unmarshall(pkiFile));
        } catch (IOException | JAXBException | SAXException | XMLStreamException e) {
            throw new PKIException(String.format("Unable to load PKI from file '%s'", pkiFile.getName()), e);
        }
    }

    /**
     * Generates certificate entries from configuration provided within {@code pki} and populates the {@code repository}
     *
     * @param repository {@link JAXBCertEntityRepository} to be populated
     * @param pki {@link XmlPki} to generate values from
     */
    public void persistPKI(JAXBCertEntityRepository repository, XmlPki pki) {
        LOG.info("PKI {} : {} certificates", pki.getName(), pki.getCertificate().size());

        final Map<EntityId, JAXBCertEntity> entities = new HashMap<>();
        final Map<EntityId, XmlCertificateType> certificateTypeMap = new HashMap<>();
        final Map<EntityId, X500Name> x500names = new HashMap<>();
        final Map<EntityId, KeyPair> keyPairs = new HashMap<>();
        buildEntities(pki.getCertificate(), entities, certificateTypeMap, x500names, keyPairs);

        JAXBCertEntity certEntity;
        for (XmlCertificateType certType : pki.getCertificate()) {

            LOG.info("Init '{}' ...", certType.getSubject());

            JAXBCertEntity issuer = getIssuer(entities, certType.getIssuer());
            String issuerName = issuer != null ? issuer.getSubject() : certType.getSubject();
            EntityId entityId = new EntityId(issuerName, certType.getSerialNumber());
            EntityId issuerId = new EntityId(certType.getIssuer());

            certEntity = entities.get(entityId);
            try {
                certificateTypeMap.put(entityId, certType);

                KeyPair subjectKeyPair = getKeyPair(keyPairs, entityId);

                boolean selfSigned = entityId.equals(issuerId);
                KeyPair issuerKeyPair = selfSigned ? subjectKeyPair : getKeyPair(keyPairs, issuerId);

                X500Name subjectX500Name = getX500Name(x500names, entityId);
                X500Name issuerX500Name = getX500Name(x500names, issuerId);

                XmlCertificateType issuerCertificate = getIssuerCertificateType(certificateTypeMap, certType, issuerId);
                CertificateToken certificateToken = buildX509Certificate(
                        certType, subjectKeyPair, issuerCertificate, issuerKeyPair, subjectX500Name, issuerX500Name);

                certEntity = buildJaxbCertEntity(certType, certEntity, certificateToken, subjectKeyPair, entityId, issuerId, entities, pki.getName());
                saveEntity(repository, certEntity);

            } catch (Exception e) {
                throw new PKIException(String.format("Unable to create a PKI. Reason : %s", e.getMessage()), e);
            }
        }

    }

    /**
     * Returns a map with pre-created {@code JAXBCertEntity}s. Required for smooth processing.
     *
     * @param certificateTypeList a list of {@link XmlCertificateType}s
     */
    private void buildEntities(List<XmlCertificateType> certificateTypeList,
            Map<EntityId, JAXBCertEntity> entities, Map<EntityId, XmlCertificateType> certificateTypeMap,
            Map<EntityId, X500Name> x500names, Map<EntityId, KeyPair> keyPairs) {

        Map<XmlCertificateType, EntityId> identifierMap = new HashMap<>();
        for (XmlCertificateType certificate : certificateTypeList) {
            EntityId entityId = getEntityId(certificate, certificateTypeList, entities, identifierMap);

            JAXBCertEntity certEntity = entities.get(entityId);
            if (certEntity == null) {
                certEntity = instantiateCertEntity(certificate);
                entities.put(entityId, certEntity);
            }

            certificateTypeMap.put(entityId, certificate);

            buildKeyPair(certificate, entityId, keyPairs);
            buildX500NameSubject(certificate, entityId, x500names);
        }
    }

    private JAXBCertEntity instantiateCertEntity(XmlCertificateType certificate) {
        JAXBCertEntity certEntity = new JAXBCertEntity();
        certEntity.setSubject(certificate.getSubject());
        certEntity.setSerialNumber(certificate.getSerialNumber());
        return certEntity;
    }

    private EntityId getEntityId(XmlCertificateType certificate, List<XmlCertificateType> certificateTypeList, Map<EntityId, JAXBCertEntity> entities, Map<XmlCertificateType, EntityId> identifierMap) {
        EntityId entityId = identifierMap.get(certificate);
        if (entityId != null) {
            return entityId;
        }
        XmlEntityKey issuerKey = certificate.getIssuer();
        // if self-signed
        if (issuerKey.getSerialNumber() != null && issuerKey.getSerialNumber() == certificate.getSerialNumber() && issuerKey.getValue().equals(certificate.getSubject())) {
            entityId = new EntityId(issuerKey);
        }
        if (entityId == null) {
            JAXBCertEntity issuer = findIssuer(certificate, certificateTypeList, entities, identifierMap);
            if (issuer != null) {
                entityId = new EntityId(issuer.getSubject(), certificate.getSerialNumber());
            }
        }
        identifierMap.put(certificate, entityId);
        return entityId;
    }

    private JAXBCertEntity findIssuer(XmlCertificateType certificate, List<XmlCertificateType> certificateTypeList, Map<EntityId, JAXBCertEntity> entities, Map<XmlCertificateType, EntityId> identifierMap) {
        EntityId issuerId = new EntityId(certificate.getIssuer());
        for (XmlCertificateType issuerCandidate : certificateTypeList) {
            if (certificate == issuerCandidate) {
                continue;
            }
            EntityId entityId = getEntityId(issuerCandidate, certificateTypeList, entities, identifierMap);
            if (issuerId.equals(entityId)) {
                JAXBCertEntity issuerCertEntity = entities.get(entityId);
                if (issuerCertEntity == null) {
                    issuerCertEntity = instantiateCertEntity(issuerCandidate);
                    entities.put(entityId, issuerCertEntity);
                }
                return issuerCertEntity;
            }
        }
        return null;
    }

    private JAXBCertEntity buildJaxbCertEntity(XmlCertificateType certificate, JAXBCertEntity certEntity, CertificateToken certificateToken,
                                               KeyPair subjectKeyPair, EntityId entityId, EntityId issuerKey,
                                               Map<EntityId, JAXBCertEntity> entities, String pkiName) {
        boolean selfSigned = entityId.equals(issuerKey);
        return new JAXBCertEntityBuilder(certEntity)
                .setCertificateToken(certificateToken)
                .setPrivateKey(subjectKeyPair.getPrivate().getEncoded())
                .setIssuer(selfSigned ? certEntity : getEntity(entities, issuerKey))
                .setRevocationDate(convert(certificate.getRevocation()))
                .setRevocationReason(certificate.getRevocation() != null ? certificate.getRevocation().getReason() : null)
                .setOcspResponder(getEntity(entities, certificate.getOcspResponder() != null ? new EntityId(certificate.getOcspResponder()) : null))
                .setTrustAnchor(certificate.getTrustAnchor() != null)
                .setPkiName(pkiName)
                .build();
    }

    private CertificateToken buildX509Certificate(XmlCertificateType certificateType, KeyPair subjectKeyPair, XmlCertificateType issuerCertificateType,
                                                  KeyPair issuerKeyPair, X500Name subjectX500Name, X500Name issuerX500Name) {
        try {
            final X509CertificateBuilder certBuilder = new X509CertificateBuilder()
                    .subject(subjectX500Name, BigInteger.valueOf(certificateType.getSerialNumber()), subjectKeyPair.getPublic());

            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forKey(issuerKeyPair.getPrivate());
            DigestAlgorithm digestAlgo = issuerCertificateType.getDigestAlgo();
            boolean pss = Utils.isTrue(issuerCertificateType.getKeyAlgo().isPss());
            MaskGenerationFunction mgf = pss ? MaskGenerationFunction.MGF1 : null;
            final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgo, mgf);
            if (signatureAlgo == null) {
                throw new IllegalArgumentException(String.format("Unable to find a SignatureAlgorithm for combination of " +
                        "[EncryptionAlgo: %s, DigestAlgo: %s, Pss: %s]", EncryptionAlgorithm.forKey(issuerKeyPair.getPrivate()), digestAlgo, pss));
            }

            certBuilder.issuer(issuerX500Name, issuerKeyPair.getPrivate(), signatureAlgo)
                    .notBefore(convert(certificateType.getNotBefore())).notAfter(convert(certificateType.getNotAfter()))
                    .caIssuers(getCAIssuersUrl(certificateType.getCaIssuers()))
                    .crl(getCrlUrl(certificateType.getCrl()))
                    .ocsp(getOcspUrl(certificateType.getOcsp()))
                    .keyUsages(certificateType.getKeyUsages() != null ? certificateType.getKeyUsages().getKeyUsage() : Collections.emptyList())
                    .certificatePolicies(certificateType.getCertificatePolicies() != null ? certificateType.getCertificatePolicies().getCertificatePolicy() : Collections.emptyList())
                    .qcStatements(certificateType.getQcStatementIds() != null ? certificateType.getQcStatementIds().getQcStatement() : Collections.emptyList())
                    .qcTypes(certificateType.getQcTypes() != null ? certificateType.getQcTypes().getQcType() : Collections.emptyList())
                    .qcCClegislations(certificateType.getQcCClegislation() != null ? certificateType.getQcCClegislation().getCountryName() : Collections.emptyList());

            if (certificateType.getCa() != null) {
                certBuilder.ca(true);
            }
            if (certificateType.getOcspNoCheck() != null) {
                certBuilder.ocspNoCheck(true);
            }

            if (certificateType.getExtendedKeyUsages() != null) {
                certBuilder.extendedKeyUsages(certificateType.getExtendedKeyUsages().getExtendedKeyUsage());
            }

            return certBuilder.build();

        } catch (Exception e) {
            throw new PKIException(String.format("Unable to build a certificate token. Reason: %s", e.getMessage()), e);
        }
    }

    /**
     * Retrieves the issuer certificate entity with the given entity key from the entities map.
     *
     * @param entities  The map of certificate entities, where the key is the EntityId and the value is the DBCertEntity.
     * @param entityKey The entity key for the issuer certificate.
     * @return The issuer certificate entity associated with the given entity key, or null if not found.
     */
    private JAXBCertEntity getIssuer(Map<EntityId, JAXBCertEntity> entities, XmlEntityKey entityKey) {
        if (entityKey.getSerialNumber() != null) {
            return entities.get(new EntityId(entityKey));
        }
        return null;
    }

    private JAXBCertEntity getEntity(Map<EntityId, JAXBCertEntity> entities, EntityId key) {
        if (key != null) {
            JAXBCertEntity certEntity = entities.get(key);
            if (certEntity == null) {
                throw new IllegalArgumentException("Entity not found " + key);
            }
            return certEntity;
        }
        return null;
    }

    private String getCrlUrl(XmlEntityKey entityKey) {
        if (entityKey != null) {
            return PKI_FACTORY_HOST + CRL_PATH + getCertStringUrl(entityKey) + CRL_EXTENSION;
        }
        return null;
    }

    private String getOcspUrl(XmlEntityKey entityKey) {
        if (entityKey != null) {
            return PKI_FACTORY_HOST + OCSP_PATH + getCertStringUrl(entityKey) + OCSP_EXTENSION;
        }
        return null;
    }

    private String getCAIssuersUrl(XmlEntityKey entityKey) {
        if (entityKey != null) {
            return PKI_FACTORY_HOST + CERT_PATH + getCertStringUrl(entityKey) + CERT_EXTENSION;
        }
        return null;
    }

    private String getCertStringUrl(XmlEntityKey entityKey) {
        return entityKey.getSerialNumber() != null ? entityKey.getValue() + "/" + entityKey.getSerialNumber() : entityKey.getValue();
    }

    private KeyPair getKeyPair(Map<EntityId, KeyPair> keyPairs, EntityId key) {
        if (keyPairs.containsKey(key)) {
            return keyPairs.get(key);
        }
        throw new IllegalStateException("EntityId not found : " + key);
    }

    private X500Name getX500Name(Map<EntityId, X500Name> x500names, EntityId key) {
        if (x500names.containsKey(key)) {
            return x500names.get(key);
        }
        throw new IllegalStateException("EntityId not found : " + key);
    }

    /**
     * Initialize subject based on given subject/organization (optional.)/country (optional.)
     *
     * @param x500Names          a map between {@link EntityId} and {@link X500Name}
     * @throws IllegalStateException Common name is null
     */
    private X500Name buildX500NameSubject(XmlCertificateType certType, EntityId entityId, Map<EntityId, X500Name> x500Names) {
        if (x500Names.containsKey(entityId)) {
            return x500Names.get(entityId);
        } else {
            if (certType.getSubject() == null) {
                throw new IllegalStateException("Missing common name for " + entityId);
            }
            String tmpCountry;
            if (!Utils.isStringEmpty(certType.getCountry())) {
                tmpCountry = certType.getCountry();
            } else {
                tmpCountry = PKI_FACTORY_COUNTRY;
            }

            String tmpOrganisation;
            if (!Utils.isStringEmpty(certType.getOrganization())) {
                tmpOrganisation = certType.getOrganization();
            } else {
                tmpOrganisation = PKI_FACTORY_ORGANISATION;
            }

            final X500Name x500Name = new X500NameBuilder()
                    .commonName(certType.getSubject()).pseudo(certType.getPseudo()).country(tmpCountry)
                    .organisation(tmpOrganisation).organisationUnit(PKI_FACTORY_ORGANISATION_UNIT)
                    .build();
            x500Names.put(entityId, x500Name);
            return x500Name;
        }
    }

    private XmlCertificateType getIssuerCertificateType(Map<EntityId, XmlCertificateType> wrapperMap, XmlCertificateType certificateType, EntityId entityId) {
        XmlCertificateType issuerCertificate = wrapperMap.get(entityId);
        if (issuerCertificate == null) {
            issuerCertificate = certificateType; // self-issued certificate
        }
        return issuerCertificate;
    }

    private KeyPair buildKeyPair(XmlCertificateType certType, EntityId entityId, Map<EntityId, KeyPair> keyPairs) {
        KeyPair keyPair = keyPairs.get(entityId);
        if (keyPair == null) {
            keyPair = build(certType.getKeyAlgo(), certType.getDigestAlgo());
            keyPairs.put(entityId, keyPair);
        }
        if (certType.getCrossCertificate() != null) {
            keyPairs.put(new EntityId(certType.getCrossCertificate()), keyPair);
        }
        return keyPair;
    }

    private KeyPair build(XmlKeyAlgo algo, DigestAlgorithm digestAlgorithm) {
        EncryptionAlgorithm encryptionAlgorithm = algo.getEncryption();
        if (EncryptionAlgorithm.EDDSA == encryptionAlgorithm) {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(algo.getEncryption(), digestAlgorithm);
            if (SignatureAlgorithm.ED25519 == signatureAlgorithm) {
                encryptionAlgorithm = EncryptionAlgorithm.X25519;
            } else if (SignatureAlgorithm.ED448 == signatureAlgorithm) {
                encryptionAlgorithm = EncryptionAlgorithm.X448;
            }
        }
        return new KeyPairBuilder(encryptionAlgorithm, algo.getLength()).build();
    }

    private Date convert(XmlDateDefinitionType ddt) {
        if (ddt != null) {
            Calendar cal = Calendar.getInstance();
            if (ddt.getYear() != null) {
                cal.add(Calendar.YEAR, ddt.getYear());
            }
            if (ddt.getMonth() != null) {
                cal.add(Calendar.MONTH, ddt.getMonth());
            }
            if (ddt.getDay() != null) {
                cal.add(Calendar.DAY_OF_MONTH, ddt.getDay());
            }
            return cal.getTime();
        }
        return null;
    }

    private void saveEntity(JAXBCertEntityRepository repository, JAXBCertEntity certEntity) {
        if (repository.save(certEntity)) {
            LOG.info("Creation of '{}' : DONE. Certificate Id : '{}'", certEntity.getSubject(), certEntity.getCertificateToken().getDSSIdAsString());
        } else {
            LOG.warn("Unable to add cert entity '{}' to the database. Certificate Id: '{}'", certEntity.getSubject(), certEntity.getCertificateToken().getDSSIdAsString());
        }
    }

}
