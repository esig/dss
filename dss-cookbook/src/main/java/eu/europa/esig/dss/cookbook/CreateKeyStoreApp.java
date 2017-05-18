package eu.europa.esig.dss.cookbook;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class CreateKeyStoreApp {

	private static final Logger LOG = LoggerFactory.getLogger(CreateKeyStoreApp.class);

	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String KEYSTORE_FILEPATH = "target/keystore.p12";
	private static final String KEYSTORE_PASSWORD = "dss-password";

	public static void main(String[] args) throws Exception {

		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource((InputStream) null, KEYSTORE_TYPE, KEYSTORE_PASSWORD);

		addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.1.cer");
		addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.2.cer");
		addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.3.cer");
		addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.4.cer");

		// PIVOT 172
		// addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.5.cer");
		// addCertificate(kscs, "src/main/resources/keystore/ec.europa.eu.6.cer");

		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		kscs.store(fos);
		Utils.closeQuietly(fos);

		LOG.info("****************");

		KeyStoreCertificateSource certificateSource = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		List<CertificateToken> certificatesFromKeyStore = certificateSource.getCertificates();
		for (CertificateToken certificateToken : certificatesFromKeyStore) {
			LOG.info("" + certificateToken);
		}
	}

	private static void addCertificate(KeyStoreCertificateSource kscs, String certPath) throws Exception {
		try (InputStream is = new FileInputStream(certPath)) {
			CertificateToken cert = DSSUtils.loadCertificate(is);
			if (cert.isExpiredOn(new Date())) {
				throw new RuntimeException("Certificate " + DSSASN1Utils.getSubjectCommonName(cert) + " is expired");
			}
			displayCertificateDigests(cert);

			LOG.info("Adding certificate " + cert);

			kscs.addCertificateToKeyStore(cert);
		}
	}

	private static void displayCertificateDigests(CertificateToken europeanCert) {
		byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, europeanCert.getEncoded());
		byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, europeanCert.getEncoded());
		LOG.info(DSSASN1Utils.getSubjectCommonName(europeanCert));
		LOG.info("SHA256 digest (Hex) : " + getPrintableHex(digestSHA256));
		LOG.info("SHA1 digest (Hex) : " + getPrintableHex(digestSHA1));
		LOG.info("SHA256 digest (Base64) : " + Utils.toBase64(digestSHA256));
		LOG.info("SHA1 digest (Base64) : " + Utils.toBase64(digestSHA1));
	}

	private static String getPrintableHex(byte[] digest) {
		String hexString = Utils.toHex(digest);
		// Add space every two characters
		return hexString.replaceAll("..", "$0 ");
	}

}
