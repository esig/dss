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
package eu.europa.esig.dss.cookbook.example;

import java.net.URL;
import java.util.Date;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

/**
 * Super-class for all cookbook examples.
 */
public class Cookbook {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

	/**
	 * The document to extend
	 */
	static protected DSSDocument toExtendDocument;

	/**
	 * The object which is in charge of digesting and encrypting the data to sign.
	 */
	static protected AbstractSignatureTokenConnection signingToken;

	/**
	 * This object contains the private key associated to the signing certificate.
	 */
	static protected DSSPrivateKeyEntry privateKey;

	/**
	 * This method converts the resource path to the absolute path.
	 *
	 * @param resourcePath
	 *            resource path
	 * @return
	 */
	public static String getPathFromResource(final String resourcePath) {

		URL uri = Cookbook.class.getResource(resourcePath);
		String absolutePath = uri.getPath();
		return absolutePath;
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void prepareXmlDoc() {
		String toSignFilePath = getPathFromResource("/xml_example.xml");
		toSignDocument = new FileDocument(toSignFilePath);
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePdfDoc() {
		String toSignFilePath = getPathFromResource("/hello-world.pdf");
		toSignDocument = new FileDocument(toSignFilePath);
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePKCS12TokenAndKey() {
		String pkcs12TokenFile = getPathFromResource("/user_a_rsa.p12");
		signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);
		privateKey = signingToken.getKeys().get(0);
	}

	protected static MockTSPSource getMockTSPSource() throws DSSException, Exception {
		return new MockTSPSource(new CertificateService().generateTspCertificate(SignatureAlgorithm.RSA_SHA256),new Date());
	}
}
