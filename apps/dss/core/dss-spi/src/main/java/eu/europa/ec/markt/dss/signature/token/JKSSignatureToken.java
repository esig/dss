/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.token;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Class holding all Java KeyStore file access logic.
 *
 * @version $Revision: 980 $ - $Date: 2011-06-16 14:17:13 +0200 (jeu., 16 juin 2011) $
 */

public class JKSSignatureToken extends AbstractSignatureTokenConnection {

	private char[] password;

	protected KeyStore keyStore = null;

	/**
	 * Creates a SignatureTokenConnection with the provided path to Java KeyStore file and password.
	 *
	 * @param ksUrlLocation
	 * @param ksPassword
	 */
	public JKSSignatureToken(String ksUrlLocation, String ksPassword) {

		InputStream ksStream = null;
		try {

			final URL ksLocation = new URL(ksUrlLocation);
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			ksStream = ksLocation.openStream();
			password = (ksPassword == null) ? null : ksPassword.toCharArray();
			keyStore.load(ksStream, password);
		} catch (CertificateException e) {
			throw new DSSException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(e);
		} catch (KeyStoreException e) {
			throw new DSSException(e);
		} catch (MalformedURLException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {

			DSSUtils.closeQuietly(ksStream);
		}
	}

	@Override
	public void close() {

		for (int ii = 0; ii < password.length; ii++) {
			password[ii] = 0;
		}
	}

	/**
	 * Retrieves all the available keys (private keys entries) from the Java KeyStore.
	 *
	 * @return
	 * @throws DSSException
	 */
	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {

		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

		try {
			final PasswordProtection pp = new KeyStore.PasswordProtection(password);
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {

				final String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {

					final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, pp);
					list.add(new KSPrivateKeyEntry(entry));
				}
			}
		} catch (UnrecoverableEntryException e) {
			throw new DSSException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(e);
		} catch (KeyStoreException e) {
			throw new DSSException(e);
		}
		return list;
	}
}
