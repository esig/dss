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
import java.security.KeyStore.PasswordProtection;

/**
 * Class holding all PKCS#12 file access logic.
 */
public class Pkcs12SignatureToken extends KeyStoreSignatureTokenConnection {

	private static final String KS_TYPE = "PKCS12";

	/**
	 * Creates a SignatureTokenConnection with the provided InputStream to PKCS#12 KeyStore file and password.
	 *
	 * @param ksStream
	 *            the inputstream
	 * @param password
	 *            the keystore password
	 */
	public Pkcs12SignatureToken(InputStream ksStream, PasswordProtection password) {
		super(ksStream, KS_TYPE, password);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided binaries to PKCS#12 KeyStore and password.
	 *
	 * @param ksBytes
	 *            the binaries
	 * @param password
	 *            the keystore password
	 */
	public Pkcs12SignatureToken(byte[] ksBytes, PasswordProtection password) {
		super(ksBytes, KS_TYPE, password);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided File to PKCS#12 KeyStore and password.
	 *
	 * @param ksFile
	 *            the keystore file
	 * @param password
	 *            the keystore password
	 * @throws IOException
	 *             if an error occurred while reading the file
	 */
	public Pkcs12SignatureToken(File ksFile, PasswordProtection password) throws IOException {
		super(ksFile, KS_TYPE, password);
	}

	/**
	 * Creates a SignatureTokenConnection with the provided filepath to PKCS#12 KeyStore file and password.
	 *
	 * @param filepath
	 *            the filepath of the keystore
	 * @param password
	 *            the keystore password
	 * @throws IOException
	 *             if an error occurred while reading the file
	 */
	public Pkcs12SignatureToken(String filepath, PasswordProtection password) throws IOException {
		super(filepath, KS_TYPE, password);
	}

}
