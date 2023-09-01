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
import eu.europa.esig.dss.pki.jaxb.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.jaxb.service.CertEntityKeystoreBuilder;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.x509.aia.PKIAIASource;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
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
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.pki.tsp.PkiTSPFailSource;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.h2.jdbcx.JdbcDataSource;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;


public abstract class PKIFactoryAccess {

    private static final String PKI_FACTORY_HOST;
    private static final char[] PKI_FACTORY_KEYSTORE_PASSWORD;

    private static final JdbcDataSource dataSource;

    static {
        try (InputStream is = PKIFactoryAccess.class.getResourceAsStream("/pki-factory.properties")) {
            Properties props = new Properties();
            props.load(is);

            PKI_FACTORY_HOST = props.getProperty("pki.factory.host");
            PKI_FACTORY_KEYSTORE_PASSWORD = props.getProperty("pki.factory.keystore.password").toCharArray();

            dataSource = new JdbcDataSource();
            dataSource.setUrl("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1");
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize from pki-factory.properties", e);
        }
    }

    private static final String KEYSTORE_ROOT_PATH = "/keystore/";
    private static final String CERT_ROOT_PATH = "/crt/";
    private static final String CERT_EXTENSION = ".crt";

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
    private static final String FAIL_GOOD_TSA = "fail/good-tsa";
    /* Produces HTTP error 500 */
    private static final String ERROR500_GOOD_TSA = "error-500/good-tsa";

    private static final String KEYSTORE_TYPE = "PKCS12";
    // JDK-7 + PKCS12 is not allowed for trust-store
    private static final String TRUSTSTORE_TYPE = "JKS";

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
    protected static final String SELF_SIGNED_USER = "self-signed";
    protected static final String EE_GOOD_USER = "ee-good-user";
    protected static final String OCSP_SKIP_USER = "ocsp-skip-user";
    protected static final String OCSP_SKIP_USER_WITH_CRL = "ocsp-skip-user-with-crl";
    protected static final String OCSP_SKIP_CA = "ocsp-skip-valid-ca";
    protected static final String OCSP_EXPIRED_RESPONDER_USER = "ocsp-skip-expired-ocsp-user";
    protected static final String OCSP_NOT_YET_VALID_CA_USER = "ocsp-skip-not-yet-valid-ca-user";
    protected static final String ROOT_CA = "root-ca";

    private static final String DEFAULT_TSA_DATE_FORMAT = "yyyy-MM-dd-HH-mm";
    private static final int TIMEOUT_MS = 10000;
    private static CommonTrustedCertificateSource trusted;

    private static CertEntityRepository<? extends CertEntity> certEntityRepository;
    private static XMLCertificateLoader certificateLoader;

    protected abstract String getSigningAlias();


    protected CertificateVerifier getEmptyCertificateVerifier() {
        return new CommonCertificateVerifier();
    }

    protected CertEntityRepository<? extends CertEntity> getCertEntityRepository() {
        if (certEntityRepository == null) {
            certEntityRepository = new JaxbCertEntityRepository();
        }
        return certEntityRepository;
    }

    protected byte[] getCertEntityKeystoreGenerator(List<CertEntity> keyEntries, List<CertEntity> certificateEntries) {
        //@formatter:off
       return new CertEntityKeystoreBuilder()
                .setKeyStorePassword("ks-password".toCharArray())
                .setKeyEntryPassword("ks-password".toCharArray())
                .setCertificateEntries(certificateEntries)
                .setKeyEntries(keyEntries)
                .setKeyStoreType("PKCS12").build();
        //@formatter:on
    }

    protected CertificateVerifier getCompleteCertificateVerifier() {
        return getCertificateVerifier(cacheOCSPSource(pKIOCSPSource()), cacheCRLSource(pKICRLSource()), cacheAIASource(pkiAIASource()), getTrustedCertificateSource());
    }

    protected CertificateVerifier getOnlineCompleteCertificateVerifier() {
        return getCertificateVerifier(cacheOCSPSource(onlineOcspSource()), cacheCRLSource(onlineCrlSource()), cacheAIASource(onlineAIASource()), getTrustedCertificateSource());
    }


    protected CertificateVerifier getOnlineNoCacheCompleteCertificateVerifier() {
        return getCertificateVerifier(onlineOcspSource(), onlineCrlSource(), onlineAIASource(), getTrustedCertificateSource());
    }


    protected CertificateVerifier getCertificateVerifierWithMGF1() {
        PKICRLSource pkicrlSource = pKICRLSource();
        pkicrlSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

        PKIOCSPSource pKIOCSPSource = pKIOCSPSource();
        pKIOCSPSource.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

        return getCertificateVerifier(pKIOCSPSource, pkicrlSource, pkiAIASource(), getTrustedCertificateSource());
    }

    protected CertificateVerifier getCertificateVerifierWithSHA3_256() {
        PKICRLSource pkicrlSource = pKICRLSource();
        pkicrlSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

        PKIOCSPSource pKIOCSPSource = pKIOCSPSource();
        pKIOCSPSource.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

        return getCertificateVerifier(pKIOCSPSource, pkicrlSource, pkiAIASource(), getTrustedCertificateSource());
    }

    private CertificateVerifier getCertificateVerifier(OCSPSource ocspSource, CRLSource crlSource, AIASource aiaSource, CertificateSource certificateSource) {
        CertificateVerifier certificateVerifier = getCertificateVerifier(ocspSource, crlSource,aiaSource);
        if (certificateSource != null){
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
        return getCertificateVerifier(cacheOCSPSource(pKIOCSPSource()), cacheCRLSource(pKICRLSource()), cacheAIASource(pkiAIASource()));
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

    protected PKICRLSource pKICRLSource() {
        PKICRLSource pkiCRLSource = new PKICRLSource(getCertEntityRepository());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 6);
        Date nextUpdate = cal.getTime();
        pkiCRLSource.setNextUpdate(nextUpdate);
        pkiCRLSource.setProductionDate(new Date());
//        onlineCRLSource.setDataLoader(getFileCacheDataLoader());
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

    protected PKIOCSPSource pKIOCSPSource() {
        return new PKIOCSPSource(getCertEntityRepository());
    }

    private OnlineOCSPSource onlineOcspSource() {
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        OCSPDataLoader dataLoader = new OCSPDataLoader();
        dataLoader.setTimeoutConnection(TIMEOUT_MS);
        dataLoader.setTimeoutSocket(TIMEOUT_MS);
        dataLoader.setProxyConfig(getProxyConfig());
        ocspSource.setDataLoader(dataLoader);
        return ocspSource;
    }

    private OnlineCRLSource onlineCrlSource() {
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
        return getPrivateKeyEntry().getCertificate();
    }

    protected CertificateToken[] getCertificateChain() {
        return getPrivateKeyEntry().getCertificateChain();
    }

    protected KSPrivateKeyEntry getPrivateKeyEntry() {
        return (KSPrivateKeyEntry) getToken().getKey(getSigningAlias());
    }

    protected AbstractKeyStoreTokenConnection getToken() {
        CertEntity certEntity = getXMLCertificateLoader().loadCertificateEntityFromXml(getSigningAlias());
        byte[] keystoreContent = getCertEntityKeystoreGenerator(Collections.singletonList(certEntity), null);
        return new KeyStoreSignatureTokenConnection(keystoreContent, KEYSTORE_TYPE, new PasswordProtection(PKI_FACTORY_KEYSTORE_PASSWORD));
    }


    private byte[] getKeystoreContent(String keystoreName) {
        keystoreName = keystoreName.substring(0, keystoreName.lastIndexOf('.'));
        List<CertEntity> certEntities = (List<CertEntity>) certEntityRepository.getTrustAnchorsByPkiName(keystoreName);
        return getCertEntityKeystoreGenerator(null, certEntities);

    }

    protected XMLCertificateLoader getXMLCertificateLoader() {

        if (certificateLoader == null) {
            certificateLoader = new XMLCertificateLoader(getCertEntityRepository());
            certificateLoader.setCommonTrustedCertificateSource(getTrustedCertificateSource());
        }
        return certificateLoader;
    }

    protected CertificateSource getTrustedCertificateSource() {
        if (trusted == null) {
            trusted = new CommonTrustedCertificateSource();
        }
        return trusted;
    }

    private KeyStoreCertificateSource getTrustAnchors() {
        byte[] keyStore = getCertEntityKeystoreGenerator(null, (List<CertEntity>) certEntityRepository.getTrustAnchors());//FIXME To be checked
        return new KeyStoreCertificateSource(new ByteArrayInputStream(keyStore), TRUSTSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
    }

    protected KeyStoreCertificateSource getSHA3PKITrustAnchors() {
        return getKeyStoreCertificateSource("sha3-pki.jks");
    }

    protected KeyStoreCertificateSource getBelgiumTrustAnchors() {
        return getKeyStoreCertificateSource("belgium.jks");
    }

    private KeyStoreCertificateSource getKeyStoreCertificateSource(String keyStoreName) {
        return new KeyStoreCertificateSource(new ByteArrayInputStream(getKeystoreContent(keyStoreName)), TRUSTSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
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

    protected PKITSPSource getGoodTsa() {
        return getPKITSPSourceByName(GOOD_TSA);
    }

    protected TSPSource getOnlineGoodTsa() {
        return getOnlineTSPSourceByName(GOOD_TSA);
    }

    protected PKITSPSource getPSSGoodTsa() {
        return getKeyStoreTSPSourceByNameWithPss(PSS_GOOD_TSA);
    }

    protected TSPSource getRSASSAPSSGoodTsa() {
        return getKeyStoreTSPSourceByNameWithPss(RSASSA_PSS_GOOD_TSA);
    }

    protected TSPSource getSHA3GoodTsa() {
        PKITSPSource tspSource = getPKITSPSourceByName(SHA3_GOOD_TSA);
        tspSource.setTstDigestAlgorithm(DigestAlgorithm.SHA3_256);
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
        entityStoreTSPSource.setEnablePSS(true);
        return entityStoreTSPSource;
    }

    protected KeyEntityTSPSource getKeyStoreTSPSourceByNameAndTime(String tsaName, Date date) {
        KeyEntityTSPSource entityStoreTSPSource = getPKITSPSourceByName(tsaName);
        entityStoreTSPSource.setProductionTime(date);
        return entityStoreTSPSource;
    }

    protected PKITSPSource getPKITSPSourceByName(String tsaName) {

        return new PKITSPSource(getCertEntityOffline(tsaName));
    }

    private CertEntity getCertEntityOffline(String tsaName) {
        return getXMLCertificateLoader().loadCertificateEntityFromXml(tsaName);
    }

    protected PkiTSPFailSource getFailPkiTspSource(String tsaName) {
        return new PkiTSPFailSource(getCertEntityOffline(tsaName));
    }

    protected PKITSPSource getPkiTSPSourceByName(String tsaName) {
        return new PKITSPSource(getCertEntityOffline(tsaName));
    }

    protected PKITSPSource getPkiTSPSourceByNameAndTime(String tsaName, Date date) {
        PKITSPSource tspSource = new PKITSPSource(getCertEntityOffline(tsaName));
        tspSource.setProductionTime(date);
        return tspSource;
    }

    protected OnlineTSPSource getOnlineTSPSourceByName(String tsaName) {
        return getOnlineTSPSourceByUrl(getTsaUrl(tsaName));
    }

    protected OnlineTSPSource getOnlineTSPSourceByNameAndTime(String tsaName, Date date) {
        return getOnlineTSPSourceByUrl(getTsaUrl(tsaName, date));
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
        return getCertEntityOffline(certificateId).getCertificateToken();
    }

    protected String getCertificateName(String certificateId) {
        return DSSUtils.encodeURI(certificateId + CERT_EXTENSION);
    }

    protected CertificateToken getCertificateByPrimaryKey(String issuerName, long serialNumber) {
        DataLoader dataLoader = getFileCacheDataLoader();
        String keystoreUrl = PKI_FACTORY_HOST + CERT_ROOT_PATH + getCertificateNameByPrimaryKey(issuerName, serialNumber);
        return DSSUtils.loadCertificate(dataLoader.get(keystoreUrl));
    }

    protected String getCertificateNameByPrimaryKey(String issuerName, long serialNumber) {
        return DSSUtils.encodeURI(issuerName + "/" + serialNumber + CERT_EXTENSION);
    }

    // Allows to configure a proxy
    protected ProxyConfig getProxyConfig() {
        return null;
    }

}
