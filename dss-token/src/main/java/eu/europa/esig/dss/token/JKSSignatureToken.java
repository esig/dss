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
package eu.europa.esig.dss.token;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/**
 * Class holding all Java KeyStore file access logic.
 *
 */
public class JKSSignatureToken extends KeyStoreSignatureTokenConnection {

	private static final String KS_TYPE = "JKS";

	/**
	 * Creates a SignatureTokenConnection with the provided InputStream to Java KeyStore file and password.
	 *
	 * @param ksStream
	 *            the inputstream
	 * @param ksPassword
	 *            the keystore password
	 */
	public JKSSignatureToken(InputStream ksStream, String ksPassword) {
		super(ksStream, KS_TYPE, ksPassword);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided binaries to Java KeyStore and password.
	 *
	 * @param ksBytes
	 *            the binaries
	 * @param ksPassword
	 *            the keystore password
	 */
	public JKSSignatureToken(byte[] ksBytes, String ksPassword) {
		super(ksBytes, KS_TYPE, ksPassword);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided File to Java KeyStore and password.
	 *
	 * @param ksFile
	 *            the keystore file
	 * @param ksPassword
	 *            the keystore password
	 */
	public JKSSignatureToken(File ksFile, String ksPassword) throws IOException {
		super(ksFile, KS_TYPE, ksPassword);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided filepath to Java KeyStore file and password.
	 *
	 * @param filepath
	 *            the filepath of the keystore
	 * @param ksPassword
	 *            the keystore password
	 */
	public JKSSignatureToken(String filepath, String ksPassword) throws IOException {
		super(filepath, KS_TYPE, ksPassword);
	}

}
