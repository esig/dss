package eu.europa.esig.dss.signature;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Properties;

import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

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
			throw new RuntimeException("Unable to initialize", e);
		}
	}

	private static final String KEYSTORE_ROOT_PATH = "/keystore/";

	private static final String TSA_ROOT_PATH = "/tsa/";
	private static final String GOOD_TSA = "good-tsa";

	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String TRUSTSTORE_TYPE = "JKS";

	protected static final String GOOD_USER = "good-user";
	protected static final String REVOKED_USER = "revoked-user";
	protected static final String EXPIRED_USER = "expired-user";

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

	private OnlineCRLSource onlineCrlSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(getProxyConfig());
		onlineCRLSource.setDataLoader(dataLoader);
		return onlineCRLSource;
	}

	protected CertificateToken getSigningCert() {
		return getPrivateKeyEntry().getCertificate();
	}

	protected CertificateToken[] getCertificateChain() {
		return getPrivateKeyEntry().getCertificateChain();
	}

	protected KSPrivateKeyEntry getPrivateKeyEntry() {
		return getToken().getKey(getSigningAlias());
	}

	protected KeyStoreSignatureTokenConnection getToken() {
		return new KeyStoreSignatureTokenConnection(getKeystoreContent(getSigningAlias() + ".p12"), KEYSTORE_TYPE, PKI_FACTORY_KEYSTORE_PASSWORD);
	}

	private byte[] getKeystoreContent(String keystoreName) {
		DataLoader dataLoader = getFileCacheDataLoader();
		String keystoreUrl = PKI_FACTORY_HOST + KEYSTORE_ROOT_PATH + keystoreName;
		return dataLoader.get(keystoreUrl);
	}

	private CertificateSource getTrustedCertificateSource() {
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

	protected OnlineTSPSource getGoodTsa() {
		OnlineTSPSource tspSource = new OnlineTSPSource(getTsaUrl(GOOD_TSA));
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
