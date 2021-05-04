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
package eu.europa.esig.dss.test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
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
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


public abstract class PKIFactoryAccess {

	private static final String PKI_FACTORY_HOST;
	private static final String PKI_FACTORY_KEYSTORE_PASSWORD;
	
	private static final JdbcDataSource dataSource;

	static {
		try (InputStream is = PKIFactoryAccess.class.getResourceAsStream("/pki-factory.properties")) {
			Properties props = new Properties();
			props.load(is);

			PKI_FACTORY_HOST = props.getProperty("pki.factory.host");
			PKI_FACTORY_KEYSTORE_PASSWORD = props.getProperty("pki.factory.keystore.password");
			
			dataSource = new JdbcDataSource();
			dataSource.setUrl("jdbc:h2:mem:test;create=true;DB_CLOSE_DELAY=-1");
		} catch (Exception e) {
			throw new RuntimeException("Unable to initialize from pki-factory.properties", e);
		}
	}

	private static final String KEYSTORE_ROOT_PATH = "/keystore/";
	private static final String CERT_ROOT_PATH = "/crt/";
	private static final String CERT_EXTENSION = ".crt";

	private static final String TSA_ROOT_PATH = "/tsa/";
	private static final String GOOD_TSA = "good-tsa";
	private static final String PSS_GOOD_TSA = "pss-good-tsa";
	private static final String RSASSA_PSS_GOOD_TSA = "rsassa-pss-good-tsa";
	private static final String SHA3_GOOD_TSA = "sha3-good-tsa";
	private static final String REVOKED_TSA = "revoked-tsa";
	private static final String EE_GOOD_TSA = "ee-good-tsa";
	private static final String GOOD_TSA_CROSS_CERTIF = "cc-good-tsa-crossed";
	private static final String SELF_SIGNED_TSA = "self-signed-tsa";

	/* Produces timestamp with a fail status */
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
	protected static final String GOOD_USER_WITH_PEM_CRL = "good-user-pem-crl";
	protected static final String REVOKED_USER = "revoked-user";
	protected static final String EXPIRED_USER = "expired-user";
	protected static final String NOT_YET_VALID_USER = "not-yet-valid-user";
	protected static final String DSA_USER = "good-dsa-user";
	protected static final String ECDSA_USER = "good-ecdsa-user";
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

	protected abstract String getSigningAlias();

	protected CertificateVerifier getEmptyCertificateVerifier() {
		return new CommonCertificateVerifier();
	}

	protected CertificateVerifier getCompleteCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setAIASource(cacheAIASource());
		cv.setCrlSource(cacheCRLSource());
		cv.setOcspSource(cacheOCSPSource());
		cv.setTrustedCertSources(getTrustedCertificateSource());
		return cv;
	}
	
	protected CertificateVerifier getCertificateVerifierWithoutTrustSources() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setAIASource(cacheAIASource());
		cv.setCrlSource(cacheCRLSource());
		cv.setOcspSource(cacheOCSPSource());
		return cv;
	}

	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setAIASource(null);
		cv.setTrustedCertSources(getTrustedCertificateSource());
		return cv;
	}

	private AIASource cacheAIASource() {
		JdbcCacheAIASource cacheAIASource = new JdbcCacheAIASource();
		cacheAIASource.setProxySource(onlineAIASource());
		JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
		cacheAIASource.setJdbcCacheConnector(jdbcCacheConnector);
		try {
			cacheAIASource.initTable();
		} catch (SQLException e) {
			throw new DSSException("Cannot initialize table for AIA certificate source.", e);
		}
		return cacheAIASource;
	}

	private DefaultAIASource onlineAIASource() {
		DefaultAIASource aiaSource = new DefaultAIASource();
		aiaSource.setDataLoader(getFileCacheDataLoader());
		return aiaSource;
	}
	
	private JdbcCacheCRLSource cacheCRLSource() {
		JdbcCacheCRLSource cacheCRLSource = new JdbcCacheCRLSource();
		cacheCRLSource.setProxySource(onlineCrlSource());
		JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
		cacheCRLSource.setJdbcCacheConnector(jdbcCacheConnector);
		cacheCRLSource.setDefaultNextUpdateDelay(3 * 24 * 60 * 60l); // 3 days
		try {
			cacheCRLSource.initTable();
		} catch (SQLException e) {
			throw new DSSException("Cannot initialize table for CRL source.", e);
		}
		return cacheCRLSource;
	}

	private OnlineCRLSource onlineCrlSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(getFileCacheDataLoader());
		return onlineCRLSource;
	}
	
	private JdbcCacheOCSPSource cacheOCSPSource() {
		JdbcCacheOCSPSource cacheOCSPSource = new JdbcCacheOCSPSource();
		cacheOCSPSource.setProxySource(onlineOcspSource());
		JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);
		cacheOCSPSource.setJdbcCacheConnector(jdbcCacheConnector);
		cacheOCSPSource.setDefaultNextUpdateDelay(3 * 60l); // 3 minutes
		try {
			cacheOCSPSource.initTable();
		} catch (SQLException e) {
			throw new DSSException("Cannot initialize table for OCSP source.", e);
		}
		return cacheOCSPSource;
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
		return new KeyStoreSignatureTokenConnection(getKeystoreContent(getSigningAlias() + ".p12"), KEYSTORE_TYPE,
				new PasswordProtection(PKI_FACTORY_KEYSTORE_PASSWORD.toCharArray()));
	}

	private byte[] getKeystoreContent(String keystoreName) {
		DataLoader dataLoader = getFileCacheDataLoader();
		String keystoreUrl = PKI_FACTORY_HOST + KEYSTORE_ROOT_PATH + keystoreName;
		return dataLoader.get(keystoreUrl);
	}

	protected CertificateSource getTrustedCertificateSource() {
		CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
		trusted.importAsTrusted(getTrustAnchors());
		return trusted;
	}
	
	private KeyStoreCertificateSource getTrustAnchors() {
		return new KeyStoreCertificateSource(new ByteArrayInputStream(getKeystoreContent("trust-anchors.jks")), TRUSTSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
	}

	protected KeyStoreCertificateSource getSHA3PKITrustAnchors() {
		return new KeyStoreCertificateSource(new ByteArrayInputStream(getKeystoreContent("sha3-pki.jks")), TRUSTSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
	}
	
	protected KeyStoreCertificateSource getBelgiumTrustAnchors() {
		return new KeyStoreCertificateSource(new ByteArrayInputStream(getKeystoreContent("belgium.jks")), TRUSTSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
	}
	
	private DataLoader getFileCacheDataLoader() {
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
		tspSources.put(FAIL_GOOD_TSA, getFailGoodTsa());
		tspSources.put(GOOD_TSA, getGoodTsa());
		tspSources.put(EE_GOOD_TSA, getAlternateGoodTsa());
		composite.setTspSources(tspSources);
		return composite;
	}

	protected TSPSource getGoodTsa() {
		return getOnlineTSPSource(GOOD_TSA);
	}

	protected TSPSource getPSSGoodTsa() {
		return getOnlineTSPSource(PSS_GOOD_TSA);
	}
	
	protected TSPSource getRSASSAPSSGoodTsa() {
		return getOnlineTSPSource(RSASSA_PSS_GOOD_TSA);
	}

	protected TSPSource getSHA3GoodTsa() {
		return getOnlineTSPSource(SHA3_GOOD_TSA);
	}

	protected TSPSource getRevokedTsa() {
		return getOnlineTSPSource(REVOKED_TSA);
	}

	protected TSPSource getFailGoodTsa() {
		return getOnlineTSPSource(FAIL_GOOD_TSA);
	}

	protected TSPSource getError500GoodTsa() {
		return getOnlineTSPSource(ERROR500_GOOD_TSA);
	}

	protected TSPSource getAlternateGoodTsa() {
		return getOnlineTSPSource(EE_GOOD_TSA);
	}

	protected TSPSource getGoodTsaCrossCertification() {
		return getOnlineTSPSource(GOOD_TSA_CROSS_CERTIF);
	}
	
	protected TSPSource getSelfSignedTsa() {
		return getOnlineTSPSource(SELF_SIGNED_TSA);
	}

	private OnlineTSPSource getOnlineTSPSource(String tsaName) {
		return getTSPSourceByUrl(getTsaUrl(tsaName));
	}
	
	protected TSPSource getGoodTsaByTime(Date date) {
		return getOnlineTSPSourceByNameAndTime(GOOD_TSA, date);
	}
	
	private OnlineTSPSource getOnlineTSPSourceByNameAndTime(String tsaName, Date date) {
		return getTSPSourceByUrl(getTsaUrl(tsaName, date));
	}
	
	private OnlineTSPSource getTSPSourceByUrl(String tsaUrl) {
		OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl);
		TimestampDataLoader dataLoader = new TimestampDataLoader();
		dataLoader.setTimeoutConnection(TIMEOUT_MS);
		dataLoader.setTimeoutSocket(TIMEOUT_MS);
		dataLoader.setProxyConfig(getProxyConfig());
		tspSource.setDataLoader(dataLoader);
		return tspSource;
	}

	private String getTsaUrl(String tsaName) {
		return PKI_FACTORY_HOST + TSA_ROOT_PATH + tsaName;
	}

	private String getTsaUrl(String tsaName, Date date) {
		String dateString = DSSUtils.formatDateWithCustomFormat(date, DEFAULT_TSA_DATE_FORMAT);
		return PKI_FACTORY_HOST + TSA_ROOT_PATH + dateString + "/" + tsaName;
	}
	
	protected CertificateToken getCertificate(String certificateId) {
		DataLoader dataLoader = getFileCacheDataLoader();
		String keystoreUrl = PKI_FACTORY_HOST + CERT_ROOT_PATH + certificateId + CERT_EXTENSION;
		return DSSUtils.loadCertificate(dataLoader.get(keystoreUrl));
	}
	
	protected CertificateToken getCertificateByPrimaryKey(String issuerName, long serialNumber) {
		DataLoader dataLoader = getFileCacheDataLoader();
		String keystoreUrl = PKI_FACTORY_HOST + CERT_ROOT_PATH + issuerName + "/" + serialNumber + CERT_EXTENSION;
		return DSSUtils.loadCertificate(dataLoader.get(keystoreUrl));
	}

	// Allows to configure a proxy
	protected ProxyConfig getProxyConfig() {
		return null;
	}

}
