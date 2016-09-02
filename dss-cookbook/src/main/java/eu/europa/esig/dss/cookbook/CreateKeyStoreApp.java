package eu.europa.esig.dss.cookbook;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class CreateKeyStoreApp {

	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String KEYSTORE_FILEPATH = "target/keystore.p12";
	private static final String KEYSTORE_PASSWORD = "dss-password";

	public static void main(String[] args) throws Exception {

		KeyStore store = createKeyStore();

		addCertificate(store, "src/main/resources/keystore/ec.europa.eu.1.cer");
		addCertificate(store, "src/main/resources/keystore/ec.europa.eu.2.cer");
		addCertificate(store, "src/main/resources/keystore/ec.europa.eu.3.cer");
		addCertificate(store, "src/main/resources/keystore/ec.europa.eu.4.cer");

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		store.store(fos, KEYSTORE_PASSWORD.toCharArray());

		Utils.closeQuietly(fos);

		readKeyStore();

		System.out.println("****************");

		KeyStoreCertificateSource certificateSource = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		List<CertificateToken> certificatesFromKeyStore = certificateSource.getCertificatesFromKeyStore();
		for (CertificateToken certificateToken : certificatesFromKeyStore) {
			System.out.println(certificateToken);
		}
	}

	private static void addCertificate(KeyStore store, String filepath) throws Exception {
		InputStream fis = new FileInputStream(filepath);
		CertificateToken europeanCert = DSSUtils.loadCertificate(fis);
		if (europeanCert.isExpiredOn(new Date())) {
			throw new RuntimeException("Certificate " + DSSASN1Utils.getSubjectCommonName(europeanCert) + " is expired");
		}
		System.out.println("Adding certificate " + filepath);
		displayCertificateDigests(europeanCert);

		// DSSID as key (used in the administration screen)
		store.setCertificateEntry(europeanCert.getDSSIdAsString(), europeanCert.getCertificate());
		Utils.closeQuietly(fis);
	}

	private static void displayCertificateDigests(CertificateToken europeanCert) {
		byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, europeanCert.getEncoded());
		byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, europeanCert.getEncoded());
		System.out.println(DSSASN1Utils.getSubjectCommonName(europeanCert));
		System.out.println("SHA256 digest (Hex) : " + getPrintableHex(digestSHA256));
		System.out.println("SHA1 digest (Hex) : " + getPrintableHex(digestSHA1));
		System.out.println("SHA256 digest (Base64) : " + Utils.toBase64(digestSHA256));
		System.out.println("SHA1 digest (Base64) : " + Utils.toBase64(digestSHA1));
	}

	private static String getPrintableHex(byte[] digest) {
		String hexString = Utils.toHex(digest);
		// Add space every two characters
		return hexString.replaceAll("..", "$0 ");
	}

	private static void readKeyStore() throws Exception {

		InputStream fis = new FileInputStream(KEYSTORE_FILEPATH);
		KeyStore store = KeyStore.getInstance(KEYSTORE_TYPE);
		store.load(fis, KEYSTORE_PASSWORD.toCharArray());

		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			if (store.isCertificateEntry(alias)) {
				Certificate certificate = store.getCertificate(alias);
				CertificateToken certificateToken = DSSUtils.loadCertificate(certificate.getEncoded());
				System.out.println(certificateToken);
			}
		}

		Utils.closeQuietly(fis);
	}

	private static KeyStore createKeyStore() throws Exception {
		KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
		trustStore.load(null, KEYSTORE_PASSWORD.toCharArray());

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		trustStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
		Utils.closeQuietly(fos);

		return trustStore;
	}

}
