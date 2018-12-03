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
package eu.europa.esig.dss.cookbook.sources;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.List;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.x509.CertificateToken;

public class JksCertificateInformation {

	public static void main(final String[] args) throws IOException {

		try (InputStream is = new FileInputStream("src/main/resources/keystore.jks");
				JKSSignatureToken jksSignatureToken = new JKSSignatureToken(is, new PasswordProtection("password".toCharArray()))) {

			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

			List<DSSPrivateKeyEntry> keys = jksSignatureToken.getKeys();
			for (DSSPrivateKeyEntry key : keys) {

				CertificateToken certificate = key.getCertificate();
				System.out.println(dateFormat.format(certificate.getNotAfter()) + ": " + certificate.getSubjectX500Principal());
				CertificateToken[] certificateChain = key.getCertificateChain();
				for (CertificateToken x509Certificate : certificateChain) {

					System.out.println("/t" + dateFormat.format(x509Certificate.getNotAfter()) + ": " + x509Certificate.getSubjectX500Principal());

				}
			}
			System.out.println("DONE");

		}
	}
}
