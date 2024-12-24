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
package eu.europa.esig.dss.cookbook.sources;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.List;

/**
 * This application prints information about each entry of a given certificate keyStore
 *
 */
public class JksCertificateInformation {

	/**
	 * Executable application
	 */
	private JksCertificateInformation() {
	}

	/**
	 * Main method
	 *
	 * @param args not applicable
	 * @throws Exception if an exception occurs
	 */
	public static void main(final String[] args) throws Exception {

		try (InputStream is = new FileInputStream("src/main/resources/keystore.jks");
			 JKSSignatureToken jksSignatureToken = new JKSSignatureToken(is, new PasswordProtection("dss-password".toCharArray()))) {

			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

			List<DSSPrivateKeyEntry> keys = jksSignatureToken.getKeys();
			for (DSSPrivateKeyEntry key : keys) {

				CertificateToken certificate = key.getCertificate();
				System.out.println(dateFormat.format(certificate.getNotAfter()) + ": " + certificate.getSubject().getCanonical());
				CertificateToken[] certificateChain = key.getCertificateChain();
				for (CertificateToken x509Certificate : certificateChain) {

					System.out.println("/t" + dateFormat.format(x509Certificate.getNotAfter()) + ": " + x509Certificate.getSubject().getCanonical());

				}
			}
			System.out.println("DONE");

		}
	}

}
