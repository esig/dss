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

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreSpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

/**
 * Class holding all MS CAPI API access logic.
 *
 */
public class MSCAPISignatureToken extends AbstractSignatureTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(MSCAPISignatureToken.class);

	private static class CallbackPasswordProtection extends KeyStore.PasswordProtection {
		PasswordInputCallback passwordCallback;

		public CallbackPasswordProtection(PasswordInputCallback callback) {
			super(null);
			this.passwordCallback = callback;
		}

		@Override
		public synchronized char[] getPassword() {
			if (passwordCallback == null) {
				throw new RuntimeException("MSCAPI: No callback provided for entering the PIN/password");
			}
			char[] password = passwordCallback.getPassword();
			return password;
		}
	}

	private PasswordInputCallback callback;

	public MSCAPISignatureToken(PasswordInputCallback callback) {
		this.callback = callback;
	}

	@Override
	public void close() {
	}

	/**
	 * This method is a workaround for scenarios when multiple entries have the same alias. Since the alias is the only "official"
	 * way of retrieving an entry, only the first entry with a given alias is accessible.
	 * See: https://joinup.ec.europa.eu/software/sd-dss/issue/problem-possible-keystore-aliases-collision-when-using-mscapi
	 *
	 * @param keyStore the key store to fix
	 */
	private static void _fixAliases(KeyStore keyStore) {
		Field field;
		KeyStoreSpi keyStoreVeritable;

		try {
			field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
				Collection<?> entries;
				String alias, hashCode;
				X509Certificate[] certificates;

				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				entries = (Collection<?>) field.get(keyStoreVeritable);

				for (Object entry : entries) {
					field = entry.getClass().getDeclaredField("certChain");
					field.setAccessible(true);
					certificates = (X509Certificate[]) field.get(entry);

					hashCode = Integer.toString(certificates[0].hashCode());

					field = entry.getClass().getDeclaredField("alias");
					field.setAccessible(true);
					alias = (String) field.get(entry);

					if (!alias.equals(hashCode)) {
						field.set(entry, alias.concat(" - ").concat(hashCode));
					}
				}
			}
		} catch (Exception exception) {
			LOG.error(exception.getMessage(), exception);
		}
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {

		List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

		try {
			ProtectionParameter protectionParameter = new CallbackPasswordProtection(new PrefilledPasswordCallback("nimp".toCharArray()));

			KeyStore keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);
			_fixAliases(keyStore);

			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {
					PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, protectionParameter);
					list.add(new KSPrivateKeyEntry(entry));
				}
			}

		} catch (Exception e) {
			throw new DSSException(e);
		}
		return list;
	}
}
