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
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.token.predicate.AllKeyEntryPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * The keyStore token connection
 */
public abstract class AbstractKeyStoreTokenConnection extends AbstractSignatureTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractKeyStoreTokenConnection.class);

	/**
	 * Filters keys obtained from token connection to be returned within {@code #getKeys()} method
	 * Default : {@code AllPrivateKeyPredicate} - returns all keys extracted from the token connection
	 */
	private Predicate<DSSPrivateKeyEntry> keyEntryPredicate = new AllKeyEntryPredicate();

	/**
	 * Default constructor
	 */
	protected AbstractKeyStoreTokenConnection() {
		// empty
	}

	/**
	 * Sets a predicate to filter keys to be returned by {@code #getKeys()} method.
	 * Default : {@code eu.europa.esig.dss.token.predicate.AllPrivateKeyPredicate} -
	 * 			returns all keys extracted from the token connection
	 *
	 * @param keyEntryPredicate {@link Predicate} of {@link DSSPrivateKeyEntry}, e.g. {@code DSSKeyEntryPredicate}
	 */
	public void setKeyEntryPredicate(Predicate<DSSPrivateKeyEntry> keyEntryPredicate) {
		Objects.requireNonNull(keyEntryPredicate, "Key entry predicate cannot be null!");
		this.keyEntryPredicate = keyEntryPredicate;
	}

	/**
	 * Gets the key store
	 *
	 * @return {@link KeyStore}
	 */
	protected abstract KeyStore getKeyStore() throws DSSException;

	/**
	 * Gets the password protection
	 *
	 * @return {@link PasswordProtection}
	 */
	protected abstract PasswordProtection getKeyProtectionParameter();

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		final List<DSSPrivateKeyEntry> list = new ArrayList<>();
		try {
			final KeyStore keyStore = getKeyStore();
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				DSSPrivateKeyEntry dssPrivateKeyEntry = getDSSPrivateKeyEntry(keyStore, alias, getKeyProtectionParameter());
				if (dssPrivateKeyEntry != null && keyEntryPredicate.test(dssPrivateKeyEntry)) {
					list.add(dssPrivateKeyEntry);
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
		final KeyStore keyStore = getKeyStore();
		return getDSSPrivateKeyEntry(keyStore, alias, passwordProtection);
	}

	private DSSPrivateKeyEntry getDSSPrivateKeyEntry(KeyStore keyStore, String alias, PasswordProtection passwordProtection) {
		try {
			if (keyStore.isKeyEntry(alias)) {
				final Entry entry = keyStore.getEntry(alias, passwordProtection);
				if (entry instanceof PrivateKeyEntry) {
					PrivateKeyEntry pke = (PrivateKeyEntry) entry;
					return new KSPrivateKeyEntry(alias, pke);
				} else {
					LOG.warn("Skipped entry (unsupported class : {})", entry.getClass().getSimpleName());
				}
			} else {
				LOG.debug("No related/supported key found for alias '{}'", alias);
			}
		} catch (GeneralSecurityException e) {
			throw new DSSException("Unable to retrieve key from keystore", e);
		}
		return null;
	}

}
