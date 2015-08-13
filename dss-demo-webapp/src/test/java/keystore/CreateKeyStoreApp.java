package keystore;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.x509.CertificateToken;

public class CreateKeyStoreApp {

	private static final String KEYSTORE_FILEPATH = "target/keystore.jks";
	private static final String KEYSTORE_PASSWORD = "dss-password";

	public static void main(String[] args) throws Exception {

		createKeyStore();

		KeyStore store = KeyStore.getInstance("JKS");
		store.load(new FileInputStream(KEYSTORE_FILEPATH), KEYSTORE_PASSWORD.toCharArray());

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);

		addCertificate(store, "src/test/resources/keystore/ec.europa.eu.crt");
		addCertificate(store, "src/test/resources/keystore/ec.europa.eu.2.crt");
		addCertificate(store, "src/test/resources/keystore/ec.europa.eu.3.crt");

		store.store(fos, KEYSTORE_PASSWORD.toCharArray());

		IOUtils.closeQuietly(fos);

		readKeyStore();
	}

	private static void addCertificate(KeyStore store, String filepath) throws Exception {
		InputStream fis = new FileInputStream(filepath);
		CertificateToken europanCert = DSSUtils.loadCertificate(fis);
		System.out.println("Adding certificate " + filepath);
		displayCertificateDigests(europanCert);

		store.setCertificateEntry(UUID.randomUUID().toString(), europanCert.getCertificate());
		IOUtils.closeQuietly(fis);
	}

	private static void displayCertificateDigests(CertificateToken europanCert) {
		byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, europanCert.getEncoded());
		byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, europanCert.getEncoded());
		System.out.println("SHA256 digest (Hex) : " + getPrintableHex(digestSHA256));
		System.out.println("SHA1 digest (Hex) : " + getPrintableHex(digestSHA1));
		System.out.println("SHA256 digest (Base64) : " + Base64.encodeBase64String(digestSHA256));
		System.out.println("SHA1 digest (Base64) : " + Base64.encodeBase64String(digestSHA1));
	}

	private static String getPrintableHex(byte[] digest) {
		String hexString = Hex.encodeHexString(digest);
		// Add space every two characters
		return hexString.replaceAll("..", "$0 ");
	}

	private static void readKeyStore() throws Exception {

		InputStream fis= new FileInputStream(KEYSTORE_FILEPATH);
		KeyStore store = KeyStore.getInstance("JKS");
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

		IOUtils.closeQuietly(fis);
	}

	private static void createKeyStore() throws Exception {
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(null, KEYSTORE_PASSWORD.toCharArray());

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		trustStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
		IOUtils.closeQuietly(fos);
	}

}
