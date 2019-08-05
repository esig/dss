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

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;

public abstract class AbstractKeyStoreTokenConnection extends AbstractSignatureTokenConnection {

	abstract KeyStore getKeyStore() throws DSSException;

	abstract PasswordProtection getKeyProtectionParameter();

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();
		try {
			final KeyStore keyStore = getKeyStore();
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {
					final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, getKeyProtectionParameter());
					list.add(new KSPrivateKeyEntry(alias, entry));
				} else {
					LOG.debug("No related/supported key found for alias '{}'", alias);
				}
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve keys from keystore", e);
		}
		return list;
	}

	/**
	 * This method allows to retrieve a DSSPrivateKeyEntry by alias
	 * 
	 * @param alias
	 *            the expected entry alias
	 * 
	 * @return the private key or null if the alias does not exist
	 */
	public DSSPrivateKeyEntry getKey(String alias) {
		return getKey(alias, getKeyProtectionParameter());
	}

	/**
	 * This method allows to retrieve a DSSPrivateKeyEntry by alias
	 * 
	 * @param alias
	 *            the expected entry alias
	 * @param passwordProtection
	 *            key password
	 * 
	 * @return the private key or null if the alias does not exist
	 */
	public DSSPrivateKeyEntry getKey(String alias, PasswordProtection passwordProtection) {
		try {
			final KeyStore keyStore = getKeyStore();
			if (keyStore.isKeyEntry(alias)) {
				final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, passwordProtection);
				return new KSPrivateKeyEntry(alias, entry);
			} else {
				LOG.debug("No related/supported key found for alias '{}'", alias);
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve key from keystore", e);
		}
		return null;
	}

}
