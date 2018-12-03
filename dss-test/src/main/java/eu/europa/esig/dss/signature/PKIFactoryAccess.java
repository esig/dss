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
package eu.europa.esig.dss.signature;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public abstract class PKIFactoryAccess {

	private static final String PKI_FACTORY_HOST;
	private static final String PKI_FACTORY_KEYSTORE_PASSWORD;

	static {
		try (InputStream is = PKIFactoryAccess.class.getResourceAsStream("/pki-factory.properties")) {
			Properties props = new Properties();
			props.load(is);

			PKI_FACTORY_HOST = props.getProperty("pki.factory.host");
			PKI_FACTORY_KEYSTORE_PASSWORD = props.getProperty("pki.factory.keystore.password");
		} catch (Exception e) {
			throw new RuntimeException("Unable to initialize from pki-factory.properties", e);
		}
	}

	private static final String KEYSTORE_ROOT_PATH = "/keystore/";

	private static final String TSA_ROOT_PATH = "/tsa/";
	private static final String GOOD_TSA = "good-tsa";
	private static final String EE_GOOD_TSA = "ee-good-tsa";
	private static final String GOOD_TSA_CROSS_CERTIF = "cc-good-tsa-crossed";

	/* Produces timestamp with a fail status */
	private static final String FAIL_GOOD_TSA = "fail/good-tsa";
	/* Produces HTTP error 500 */
	private static final String ERROR500_GOOD_TSA = "error-500/good-tsa";

	private static final String KEYSTORE_TYPE = "PKCS12";
	// JDK-7 + PKCS12 is not allowed for trust-store
	private static final String TRUSTSTORE_TYPE = "JKS";

	protected static final String GOOD_USER = "good-user";
	protected static final String UNTRUSTED_USER = "untrusted-user";
	protected static final String GOOD_USER_WRONG_AIA = "good-user-wrong-aia";
	protected static final String GOOD_USER_OCSP_ERROR_500 = "good-user-ocsp-error-500";
	protected static final String GOOD_USER_OCSP_FAIL = "good-user-ocsp-fail";
	protected static final String GOOD_USER_CROSS_CERTIF = "cc-good-user-crossed";
	protected static final String REVOKED_USER = "revoked-user";
	protected static final String EXPIRED_USER = "expired-user";
	protected static final String DSA_USER = "good-dsa-user";
	protected static final String ECDSA_USER = "good-ecdsa-user";
	protected static final String RSA_SHA3_USER = "sha3-good-user";
	protected static final String SELF_SIGNED_USER = "self-signed";

	protected abstract String getSigningAlias();

	protected CertificateVerifier getEmptyCertificateVerifier() {
		return new CommonCertificateVerifier();
	}

	protected CertificateVerifier getCompleteCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(getFileCacheDataLoader());
		cv.setCrlSource(onlineCrlSource());
		cv.setOcspSource(onlineOcspSource());
		cv.setTrustedCertSource(getTrustedCertificateSource());
		return cv;
	}

	protected CertificateVerifier getOfflineCertificateVerifier() {
		CertificateVerifier cv = new CommonCertificateVerifier();
		cv.setDataLoader(new IgnoreDataLoader());
		cv.setTrustedCertSource(getTrustedCertificateSource());
		return cv;
	}

	private OnlineCRLSource onlineCrlSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(getFileCacheDataLoader());
		return onlineCRLSource;
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

	private OnlineOCSPSource onlineOcspSource() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPDataLoader dataLoader = new OCSPDataLoader();
		dataLoader.setProxyConfig(getProxyConfig());
		ocspSource.setDataLoader(dataLoader);
		return ocspSource;
	}

	private DataLoader getFileCacheDataLoader() {
		FileCacheDataLoader cacheDataLoader = new FileCacheDataLoader();
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(getProxyConfig());
		cacheDataLoader.setDataLoader(dataLoader);
		cacheDataLoader.setFileCacheDirectory(new File("target"));
		cacheDataLoader.setCacheExpirationTime(3600000L);
		return cacheDataLoader;
	}

	protected TSPSource getCompositeTsa() {
		CompositeTSPSource composite = new CompositeTSPSource();
		Map<String, TSPSource> tspSources = new HashMap<String, TSPSource>();
		tspSources.put(FAIL_GOOD_TSA, getFailGoodTsa());
		tspSources.put(GOOD_TSA, getGoodTsa());
		tspSources.put(EE_GOOD_TSA, getAlternateGoodTsa());
		composite.setTspSources(tspSources);
		return composite;
	}

	protected TSPSource getGoodTsa() {
		return getOnlineTSPSource(GOOD_TSA);
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

	private OnlineTSPSource getOnlineTSPSource(String tsaName) {
		OnlineTSPSource tspSource = new OnlineTSPSource(getTsaUrl(tsaName));
		TimestampDataLoader dataLoader = new TimestampDataLoader();
		dataLoader.setProxyConfig(getProxyConfig());
		tspSource.setDataLoader(dataLoader);
		return tspSource;
	}

	private String getTsaUrl(String tsaName) {
		return PKI_FACTORY_HOST + TSA_ROOT_PATH + tsaName;
	}

	// Allows to configure a proxy
	protected ProxyConfig getProxyConfig() {
		return null;
	}

}
