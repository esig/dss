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
package eu.europa.esig.dss.cookbook;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

/**
 * This application can be used to create a certificate keyStore
 *
 */
public class CreateKeyStoreApp {

	private static final Logger LOG = LoggerFactory.getLogger(CreateKeyStoreApp.class);

	private static final boolean ALLOW_EXPIRED = false;
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String KEYSTORE_FILEPATH = "target/keystore.p12";

	/**
	 * Main method
	 *
	 * @param args not applicable
	 * @throws Exception if an exception occurs
	 */
	public static void main(String[] args) throws Exception {

		KeyStoreCertificateSource kscs = new KeyStoreCertificateSource((InputStream) null, KEYSTORE_TYPE, getKeystorePassword());

		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.1.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.2.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.3.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.4.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.5.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.6.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.7.cer");
		addCertificate(kscs, "src/main/resources/oj_2019/ec.europa.eu.8.cer");


		OutputStream fos = new FileOutputStream(KEYSTORE_FILEPATH);
		kscs.store(fos);
		Utils.closeQuietly(fos);

		LOG.info("****************");

		KeyStoreCertificateSource certificateSource = new KeyStoreCertificateSource(new File(KEYSTORE_FILEPATH), KEYSTORE_TYPE, getKeystorePassword());
		List<CertificateToken> certificatesFromKeyStore = certificateSource.getCertificates();
		for (CertificateToken certificateToken : certificatesFromKeyStore) {
			LOG.info("{}", certificateToken);
		}
	}

	private static void addCertificate(KeyStoreCertificateSource kscs, String certPath) throws Exception {
		try (InputStream is = new FileInputStream(certPath)) {
			CertificateToken cert = DSSUtils.loadCertificate(is);
			if (!ALLOW_EXPIRED && !cert.isValidOn(new Date())) {
				LOG.error("Certificate is out of bounds : {}", cert);
				throw new DSSException(String.format("Certificate %s cannot be added to the keyStore! "
						+ "Renew the certificate or change ALLOW_EXPIRED value to true.", DSSASN1Utils.getSubjectCommonName(cert)));
			}
			displayCertificateDigests(cert);

			LOG.info("Adding certificate {}", cert);

			kscs.addCertificateToKeyStore(cert);
		}
	}

	private static void displayCertificateDigests(CertificateToken europeanCert) {
		byte[] digestSHA256 = DSSUtils.digest(DigestAlgorithm.SHA256, europeanCert.getEncoded());
		byte[] digestSHA1 = DSSUtils.digest(DigestAlgorithm.SHA1, europeanCert.getEncoded());
		LOG.info(DSSASN1Utils.getSubjectCommonName(europeanCert));
		LOG.info("SHA256 digest (Hex) : {}", getPrintableHex(digestSHA256));
		LOG.info("SHA1 digest (Hex) : {}", getPrintableHex(digestSHA1));
		LOG.info("SHA256 digest (Base64) : {}", Utils.toBase64(digestSHA256));
		LOG.info("SHA1 digest (Base64) : {}", Utils.toBase64(digestSHA1));
	}

	private static String getPrintableHex(byte[] digest) {
		String hexString = Utils.toHex(digest);
		// Add space every two characters
		return hexString.replaceAll("..", "$0 ");
	}

	/* Not defined as constant (sonar check) */
	private static String getKeystorePassword() {
		return "dss-password";
	}

}
