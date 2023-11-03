/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.x509.aia.PKIAIASource;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIDelegatedOCSPSource;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import eu.europa.esig.dss.pki.x509.tsp.PKITSPSource;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.service.x509.aia.JdbcCacheAIASource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.CompositeRevocationSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.CompositeAIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.pki.CertEntitySignatureTokenConnection;
import eu.europa.esig.dss.test.pki.tsp.PkiTSPFailSource;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.h2.jdbcx.JdbcDataSource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;


public abstract class PKIFactoryAccess {

    private static final String PKI_FACTORY_HOST;

    private static final char[] PKI_FACTORY_KEYSTORE_PASSWORD;
    private static final String PKI_FACTORY_KEYSTORE_PATH;

    private static final String PKI_FACTORY_RESOURCES_FOLDER;
    private static final String[] PKI_FACTORY_RESOURCES_FILENAMES;

    private static final JdbcDataSource dataSource;

    static {
        try (InputStream is = PKIFactoryAccess.class.getResourceAsStream("/pki-factory.properties")) {
            Properties props = new Properties();
            props.load(is);

            PKI_FACTORY_HOST = props.getProperty("pki.factory.host");
            PKI_FACTORY_KEYSTORE_PASSWORD = props.getProperty("pki.factory.keystore.password").toCharArray();
            PKI_FACTORY_KEYSTORE_PATH = props.getProperty("pki.factory.keystore.path");

            PKI_FACTORY_RESOURCES_FOLDER = props.getProperty("pki.factory.resources.folder");
            PKI_FACTORY_RESOURCES_FILENAMES = Arrays.stream(props.getProperty("pki.factory.resources.filenames").split(",")).map(String::trim).toArray(String[]::new);

            dataSource = new JdbcDataSource();
            dataSource.setUrl("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1");
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize from pki-factory.properties", e);
        }
    }

    private static final String TSA_ROOT_PATH = "/tsa/";
    protected static final String GOOD_TSA = "good-tsa";
    protected static final String PSS_GOOD_TSA = "pss-good-tsa";
    protected static final String RSASSA_PSS_GOOD_TSA = "rsassa-pss-good-tsa";
    protected static final String SHA3_GOOD_TSA = "sha3-good-tsa";
    protected static final String REVOKED_TSA = "revoked-tsa";
    protected static final String EE_GOOD_TSA = "ee-good-tsa";
    protected static final String GOOD_TSA_CROSS_CERTIF = "cc-good-tsa-crossed";
    protected static final String SELF_SIGNED_TSA = "self-signed-tsa";

    /* Produces timestamp with a fail status */
    private static final String FAIL_GOOD_TSA_ONLINE = "fail/good-tsa";
    protected static final String FAIL_GOOD_TSA = "fail/good-tsa";
    /* Produces HTTP error 500 */
    private static final String ERROR500_GOOD_TSA = "error-500/good-tsa";

    protected static final String GOOD_USER = "good-user";
    // RSA key with RSASSA-PSS signature
    protected static final String PSS_GOOD_USER = "pss-good-user";
    // RSASSA-PSS key with RSASSA-PSS signature
    protected static final String RSASSA_PSS_GOOD_USER = "rsassa-pss-good-user";
    protected static final String ED25519_GOOD_USER = "Ed25519-good-user";
    protected static final String ED448_GOOD_USER = "Ed448-good-user";
    protected static final String UNTRUSTED_USER = "untrusted-user";
    protected static final String GOOD_USER_WRONG_AIA = "good-user-wrong-aia";
    protected static final String GOOD_USER_OCSP_ERROR_500 = "good-user-ocsp-error-500";
    protected static final String GOOD_USER_OCSP_FAIL = "good-user-ocsp-fail";
    protected static final String GOOD_USER_UNKNOWN = "good-user-suspended";
    protected static final String GOOD_USER_CROSS_CERTIF = "cc-good-user-crossed";
    protected static final String GOOD_USER_WITH_PSEUDO = "good-user-with-pseudo";
    protected static final String GOOD_USER_WITH_CRL_AND_OCSP = "good-user-crl-ocsp";
    protected static final String GOOD_USER_WITH_OCSP_CERT_ID_DIGEST = "good-user-ocsp-certid-digest";
    protected static final String GOOD_USER_WITH_PEM_CRL = "good-user-pem-crl";
    protected static final String REVOKED_USER = "revoked-user";
    protected static final String EXPIRED_USER = "expired-user";
    protected static final String NOT_YET_VALID_USER = "not-yet-valid-user";
    protected static final String DSA_USER = "good-dsa-user";
    protected static final String ECDSA_USER = "good-ecdsa-user";
    protected static final String ECDSA_384_USER = "good-ecdsa-384-user";
    protected static final String ECDSA_521_USER = "good-ecdsa-521-user";
    protected static final String RSA_SHA3_USER = "sha3-good-user";
    protected static final String SHA3_OCSP_RESPONDER = "sha3-ocsp-responder";
    protected static final String SELF_SIGNED_USER = "self-signed";
    protected static final String EE_GOOD_USER = "ee-good-user";
    protected static final String OCSP_SKIP_USER = "ocsp-skip-user";
    protected static final String OCSP_SKIP_USER_WITH_CRL = "ocsp-skip-user-with-crl";
    protected static final String OCSP_SKIP_CA = "ocsp-skip-valid-ca";
    protected static final String OCSP_EXPIRED_RESPONDER_USER = "ocsp-skip-expired-ocsp-user";
    protected static final String OCSP_NOT_YET_VALID_CA_USER = "ocsp-skip-not-yet-valid-ca-user";
    protected static final String ROOT_CA = "root-ca";

    private static final String DEFAULT_TSA_DATE_FORMAT = "yyyy-MM-dd-HH-mm";
    private static final String DEFAULT_TSA_POLICY = "1.2.3.4";
    private static final int TIMEOUT_MS = 10000;
    private static CommonTrustedCertificateSource trustedCertificateSource;

    private static JAXBCertEntityRepository certEntityRepository;
    private static JAXBPKICertificateLoader certificateLoader;

    protected abstract String getSigningAlias();


    protected CertificateVerifier getEmptyCertificateVerifier() {
        return new CommonCertificateVerifier();
    }

    protected JAXBCertEntityRepository getCertEntityRepository() {
        if (certEntityRepository == null) {
            certEntityRepository = new JAXBCertEntityRepository();
        }
        return certEntityRepository;
    }

    protected CertificateVerifier getCompleteCertificateVerifier() {
        return getCertificateVerifier(cacheOCSPSource(pkiDelegatedOCSPSource()), cacheCRLSource(pkiCRLSource()), cacheAIASource(pkiAIASource()), getTrustedCertificateSource());
    }

    protected CertificateVerifier getCompositeCertificateVerifier() {
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCrlSource(getCompositeCRLSource());
        certificateVerifier.setOcspSource(getCompositeOCSPSource());
        certificateVerifier.setAIASource(getCompositeAia());
        certificateVerifier.setTrustedCertSources(getTrustedCertificateSource());
        return certificateVerifier;
    }

    protected CertificateVerifier getCertificateVerifierWithMGF1() {
        PKICRLSource pkicrlSource = pkiCRLSource();
        pkicrlSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

        PKIOCSPSource pKIOCSPSource = pkiOCSPSource();
        pKIOCSPSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

        return getCertificateVerifier(pKIOCSPSource, pkicrlSource, pkiAIASource(), getTrustedCertificateSource());
    }

    protected CertificateVerifier getCertificateVerifierWithSHA3_256() {
        PKICRLSource pkicrlSource = pkiCRLSource();
        pkicrlSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

        PKIOCSPSource pKIOCSPSource = pkiOCSPSource();
        pKIOCSPSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        pKIOCSPSource.setOcspResponder(getPKICertEntity(SHA3_OCSP_RESPONDER));

        return getCertificateVerifier(pKIOCSPSource, pkicrlSource, pkiAIASource(), getTrustedCertificateSource());
    }

    private CertificateVerifier getCertificateVerifier(OCSPSource ocspSource, CRLSource crlSource, AIASource aiaSource, CertificateSource certificateSource) {
        CertificateVerifier certificateVerifier = getCertificateVerifier(ocspSource, crlSource, aiaSource);
        if (certificateSource != null) {
            certificateVerifier.setTrustedCertSources(certificateSource);
        }
        return certificateVerifier;
    }

    private CertificateVerifier getCertificateVerifier(OCSPSource ocspSource, CRLSource crlSource, AIASource aiaSource) {
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCrlSource(crlSource);
        certificateVerifier.setOcspSource(ocspSource);
        certificateVerifier.setAIASource(aiaSource);
        return certificateVerifier;
    }

    protected CertificateVerifier getCertificateVerifierWithoutTrustSources() {
        return getCertificateVerifier(cacheOCSPSource(pkiOCSPSource()), cacheCRLSource(pkiCRLSource()), cacheAIASource(pkiAIASource()));
    }

    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(null);
        cv.setTrustedCertSources(getTrustedCertificateSource());
        return cv;
    }

    private AIASource cacheAIASource(AIASource aiaSource) {
        JdbcCacheAIASource cacheAIASource = new JdbcCacheAIASource();
        cacheAIASource.setProxySource(aiaSource);
        JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
        cacheAIASource.setJdbcCacheConnector(jdbcCacheConnector);
        try {
            cacheAIASource.initTable();
        } catch (SQLException e) {
            throw new DSSException("Cannot initialize table for AIA certificate source.", e);
        }
        return cacheAIASource;
    }

    protected PKIAIASource pkiAIASource() {
        return new PKIAIASource(getCertEntityRepository());
    }

    private JdbcCacheCRLSource cacheCRLSource(RevocationSource<CRL> revocationSource) {
        JdbcCacheCRLSource cacheCRLSource = new JdbcCacheCRLSource();
        cacheCRLSource.setProxySource(revocationSource);
        JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
        cacheCRLSource.setJdbcCacheConnector(jdbcCacheConnector);
        cacheCRLSource.setDefaultNextUpdateDelay(3 * 24 * 60 * 60L); // 3 days
        try {
            cacheCRLSource.initTable();
        } catch (SQLException e) {
            throw new DSSException("Cannot initialize table for CRL source.", e);
        }
        return cacheCRLSource;
    }

    protected PKICRLSource pkiCRLSource() {
        PKICRLSource pkiCRLSource = new PKICRLSource(getCertEntityRepository());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();
        pkiCRLSource.setNextUpdate(nextUpdate);
        return pkiCRLSource;
    }

    private JdbcCacheOCSPSource cacheOCSPSource(RevocationSource<OCSP> revocationSource) {
        JdbcCacheOCSPSource cacheOCSPSource = new JdbcCacheOCSPSource();
        cacheOCSPSource.setProxySource(revocationSource);
        JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
        cacheOCSPSource.setJdbcCacheConnector(jdbcCacheConnector);
        cacheOCSPSource.setDefaultNextUpdateDelay(3 * 60 * 60L); // 3 hours
        try {
            cacheOCSPSource.initTable();
        } catch (SQLException e) {
            throw new DSSException("Cannot initialize table for OCSP source.", e);
        }
        return cacheOCSPSource;
    }

    protected PKIOCSPSource pkiOCSPSource() {
        return new PKIOCSPSource(getCertEntityRepository());
    }

    protected PKIDelegatedOCSPSource pkiDelegatedOCSPSource() {
        PKIDelegatedOCSPSource pkiDelegatedOCSPSource = new PKIDelegatedOCSPSource(getCertEntityRepository());

        Map<CertEntity, CertEntity> ocspResponders = getCertEntityRepository().getAll()
                .stream().filter(dbCertEntity -> dbCertEntity.getOcspResponder() != null)
                .collect(Collectors.toMap(d -> d, JAXBCertEntity::getOcspResponder));
        pkiDelegatedOCSPSource.setOcspResponders(ocspResponders);

        return pkiDelegatedOCSPSource;
    }

    private OnlineOCSPSource onlineOCSPSource() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        OCSPDataLoader dataLoader = new OCSPDataLoader();
        dataLoader.setTimeoutConnection(TIMEOUT_MS);
        dataLoader.setTimeoutSocket(TIMEOUT_MS);
        dataLoader.setProxyConfig(getProxyConfig());
        ocspSource.setDataLoader(dataLoader);
        return ocspSource;
    }

    private OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(getFileCacheDataLoader());
        return onlineCRLSource;
    }

    private DefaultAIASource onlineAIASource() {
        DefaultAIASource aiaSource = new DefaultAIASource();
        aiaSource.setDataLoader(getFileCacheDataLoader());
        return aiaSource;
    }

    protected CertificateToken getSigningCert() {
        return getCertEntity().getCertificateToken();
    }

    protected CertificateToken[] getCertificateChain() {
        return getCertEntity().getCertificateChain().toArray(new CertificateToken[0]);
    }

    protected CertEntity getCertEntity() {
        return getXMLCertificateLoader().loadCertificateEntityFromXml(getSigningAlias());
    }

    protected AbstractSignatureTokenConnection getToken() {
        return new CertEntitySignatureTokenConnection(getCertEntity());
    }

    protected DSSPrivateKeyEntry getPrivateKeyEntry() {
        return getToken().getKeys().iterator().next();
    }

    protected JAXBPKICertificateLoader getXMLCertificateLoader() {
        if (certificateLoader == null) {
            certificateLoader = new JAXBPKICertificateLoader(getCertEntityRepository());
            certificateLoader.setPkiFolder(PKI_FACTORY_RESOURCES_FOLDER);
            certificateLoader.setPkiFilenames(PKI_FACTORY_RESOURCES_FILENAMES);
            certificateLoader.setCommonTrustedCertificateSource((CommonTrustedCertificateSource) getTrustedCertificateSource());
        }
        return certificateLoader;
    }

    protected CertificateSource getTrustedCertificateSource() {
        if (trustedCertificateSource == null) {
            trustedCertificateSource = new CommonTrustedCertificateSource();
        }
        return trustedCertificateSource;
    }

    protected CertificateSource getSHA3PKITrustAnchors() {
        return getTrustedCertificateSourceByPKIName("sha3-pki");
    }

    protected CertificateSource getGoodPKITrustAnchors() {
        return getTrustedCertificateSourceByPKIName("good-pki");
    }

    private CertificateSource getTrustedCertificateSourceByPKIName(String pkiName) {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        List<JAXBCertEntity> certEntities = certEntityRepository.getByPkiName(pkiName);
        if (Utils.isCollectionNotEmpty(certEntities)) {
            certEntities.stream().filter(JAXBCertEntity::isTrustAnchor).map(JAXBCertEntity::getCertificateToken).forEach(trustedCertificateSource::addCertificate);
        }
        return trustedCertificateSource;
    }

    protected AbstractKeyStoreTokenConnection getOnlinePKCS12Token() {
        return new KeyStoreSignatureTokenConnection(getOnlineKeystoreContent(getPKCS12KeystoreName()), "PKCS12",
                new KeyStore.PasswordProtection(PKI_FACTORY_KEYSTORE_PASSWORD));
    }

    protected byte[] getOnlineKeystoreContent(String keystoreName) {
        DataLoader dataLoader = getFileCacheDataLoader();
        String keystoreUrl = PKI_FACTORY_HOST + PKI_FACTORY_KEYSTORE_PATH + keystoreName;
        return dataLoader.get(keystoreUrl);
    }

    protected String getPKCS12KeystoreName() {
        return DSSUtils.encodeURI(getSigningAlias() + ".p12");
    }

    protected CertificateSource getOnlineTrustedCertificateSource() {
        byte[] trustedStoreContent = getOnlineKeystoreContent("trust-anchors.jks");
        KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(new ByteArrayInputStream(trustedStoreContent), "JKS", PKI_FACTORY_KEYSTORE_PASSWORD);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.importAsTrusted(keystore);
        return trustedCertificateSource;
    }

    protected DataLoader getFileCacheDataLoader() {
        FileCacheDataLoader cacheDataLoader = new FileCacheDataLoader();
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        dataLoader.setProxyConfig(getProxyConfig());
        dataLoader.setTimeoutConnection(TIMEOUT_MS);
        dataLoader.setTimeoutSocket(TIMEOUT_MS);
        cacheDataLoader.setDataLoader(dataLoader);
        cacheDataLoader.setFileCacheDirectory(new File("target"));
        cacheDataLoader.setCacheExpirationTime(3600000L);
        return cacheDataLoader;
    }

    protected TSPSource getCompositeTsa() {
        CompositeTSPSource composite = new CompositeTSPSource();
        Map<String, TSPSource> tspSources = new HashMap<>();
        tspSources.put(FAIL_GOOD_TSA, getFailPkiTspSource(GOOD_TSA));
        tspSources.put(GOOD_TSA, getPKITSPSourceByName(GOOD_TSA));
        tspSources.put(EE_GOOD_TSA, getPKITSPSourceByName(EE_GOOD_TSA));
        composite.setTspSources(tspSources);
        return composite;
    }

    protected AIASource getCompositeAia() {
        CompositeAIASource composite = new CompositeAIASource();
        LinkedHashMap<String, AIASource> aiaSources = new LinkedHashMap<>();
        aiaSources.put("PkiAIASource", pkiAIASource());
        aiaSources.put("OnlineAIASource", onlineAIASource());

        composite.setAIASources(aiaSources);
        return composite;
    }

    protected CompositeRevocationSource<CRL, CRLSource> getCompositeCRLSource() {
        CompositeRevocationSource<CRL, CRLSource> composite = new CompositeRevocationSource<>();
        LinkedHashMap<String, CRLSource> crlSources = new LinkedHashMap<>();
        crlSources.put("PKICRLSource", pkiCRLSource());
        crlSources.put("OnlineCrlSource", onlineCRLSource());
        composite.setSources(crlSources);
        return composite;
    }

    protected CompositeRevocationSource<OCSP, OCSPSource> getCompositeOCSPSource() {
        CompositeRevocationSource<OCSP, OCSPSource> composite = new CompositeRevocationSource<>();
        LinkedHashMap<String, OCSPSource> ocspSources = new LinkedHashMap<>();
        ocspSources.put("PKIOCSPSource", pkiOCSPSource());
        ocspSources.put("OnlineOCSPSource", onlineOCSPSource());
        composite.setSources(ocspSources);
        return composite;
    }

    protected PKITSPSource getGoodTsa() {
        return getPKITSPSourceByName(GOOD_TSA);
    }

    protected PKITSPSource getPSSGoodTsa() {
        return getKeyStoreTSPSourceByNameWithPss(PSS_GOOD_TSA);
    }

    protected TSPSource getRSASSAPSSGoodTsa() {
        return getKeyStoreTSPSourceByNameWithPss(RSASSA_PSS_GOOD_TSA);
    }

    protected TSPSource getSHA3GoodTsa() {
        PKITSPSource tspSource = getPKITSPSourceByName(SHA3_GOOD_TSA);
        tspSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);
        return tspSource;
    }

    protected TSPSource getRevokedTsa() {
        return getPKITSPSourceByName(REVOKED_TSA);
    }

    protected TSPSource getOnlineFailGoodTsa() {
        return getOnlineTSPSourceByName(FAIL_GOOD_TSA_ONLINE);
    }

    protected TSPSource getError500GoodTsa() {
        return getOnlineTSPSourceByName(ERROR500_GOOD_TSA);
    }

    protected TSPSource getAlternateGoodTsa() {
        return getPKITSPSourceByName(EE_GOOD_TSA);
    }

    protected TSPSource getGoodTsaCrossCertification() {
        return getPKITSPSourceByName(GOOD_TSA_CROSS_CERTIF);
    }

    protected TSPSource getSelfSignedTsa() {
        return getPKITSPSourceByName(SELF_SIGNED_TSA);
    }

    protected TSPSource getGoodTsaByTime(Date date) {
        return getKeyStoreTSPSourceByNameAndTime(GOOD_TSA, date);
    }

    protected PKITSPSource getKeyStoreTSPSourceByNameWithPss(String tsaName) {
        PKITSPSource entityStoreTSPSource = getPKITSPSourceByName(tsaName);
        entityStoreTSPSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);
        return entityStoreTSPSource;
    }

    protected KeyEntityTSPSource getKeyStoreTSPSourceByNameAndTime(String tsaName, Date date) {
        KeyEntityTSPSource entityStoreTSPSource = getPKITSPSourceByName(tsaName);
        entityStoreTSPSource.setProductionTime(date);
        return entityStoreTSPSource;
    }

    protected PKITSPSource getPKITSPSourceByName(String tsaName) {
        PKITSPSource tspSource = new PKITSPSource(getPKICertEntity(tsaName));
        tspSource.setTsaPolicy(DEFAULT_TSA_POLICY);
        return tspSource;
    }

    private CertEntity getPKICertEntity(String certEntityName) {
        return getXMLCertificateLoader().loadCertificateEntityFromXml(certEntityName);
    }

    protected PkiTSPFailSource getFailPkiTspSource(String tsaName) {
        return new PkiTSPFailSource(getPKICertEntity(tsaName));
    }

    protected OnlineTSPSource getOnlineTSPSourceByName(String tsaName) {
        return getOnlineTSPSourceByUrl(getTsaUrl(tsaName));
    }

    private OnlineTSPSource getOnlineTSPSourceByUrl(String tsaUrl) {
        OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl);
        TimestampDataLoader dataLoader = new TimestampDataLoader();
        dataLoader.setTimeoutConnection(TIMEOUT_MS);
        dataLoader.setTimeoutSocket(TIMEOUT_MS);
        dataLoader.setProxyConfig(getProxyConfig());
        tspSource.setDataLoader(dataLoader);
        return tspSource;
    }

    private String getTsaUrl(String tsaName) {
        return getTsaUrl(tsaName, null);
    }

    private String getTsaUrl(String tsaName, Date date) {
        StringBuilder sb = new StringBuilder();
        sb.append(PKI_FACTORY_HOST);
        sb.append(TSA_ROOT_PATH);
        if (date != null) {
            String dateString = DSSUtils.formatDateWithCustomFormat(date, DEFAULT_TSA_DATE_FORMAT);
            sb.append(dateString);
            sb.append('/');
        }
        sb.append(tsaName);
        return sb.toString();
    }

    protected CertificateToken getCertificate(String certificateId) {
        return getPKICertEntity(certificateId).getCertificateToken();
    }

    protected CertificateToken getCertificateByPrimaryKey(long serialNumber, String issuerName) {
        return getXMLCertificateLoader().loadCertificateEntityFromXml(serialNumber, issuerName).getCertificateToken();
    }

    // Allows to configure a proxy
    protected ProxyConfig getProxyConfig() {
        return null;
    }

}
