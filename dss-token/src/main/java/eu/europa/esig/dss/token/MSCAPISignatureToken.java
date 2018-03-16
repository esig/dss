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

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreSpi;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

/**
 * Class holding all MS CAPI API access logic.
 *
 */
public class MSCAPISignatureToken extends AbstractKeyStoreTokenConnection {

	private static final Logger LOG = LoggerFactory.getLogger(MSCAPISignatureToken.class);

	/**
	 * This method is a workaround for scenarios when multiple entries have the same alias. Since the alias is the only
	 * "official" way of retrieving an entry, only the first entry with a given alias is accessible.
	 * See:
	 * https://joinup.ec.europa.eu/software/sd-dss/issue/problem-possible-keystore-aliases-collision-when-using-mscapi
	 *
	 * @param keyStore
	 *            the key store to fix
	 */
	private static void _fixAliases(KeyStore keyStore) {
		Field field;
		KeyStoreSpi keyStoreVeritable;

		try {
			field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {

				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				Object entriesObject = field.get(keyStoreVeritable);
				if (entriesObject instanceof Map) {
					// Old issue fixed in JDK 7u121 and JDK8
					// More info :
					// https://bugs.openjdk.java.net/browse/JDK-6483657
					// http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/0901dc70ae2b
					return;
				} else if (entriesObject instanceof Collection<?>) {
					Collection<?> entries = (Collection<?>) entriesObject;
					String alias, hashCode;
					X509Certificate[] certificates;

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
				} else {
					LOG.warn("Unsupported entries type : " + entriesObject.getClass().getName());
				}
			}
		} catch (Exception exception) {
			LOG.error(exception.getMessage(), exception);
		}
	}

	@Override
	KeyStore getKeyStore() throws DSSException {
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);
			_fixAliases(keyStore);
		} catch (IOException | GeneralSecurityException e) {
			throw new DSSException("Unable to load MS CAPI keystore", e);
		}
		return keyStore;
	}

	@Override
	PasswordProtection getKeyProtectionParameter() {
		return new PasswordProtection("nimp".toCharArray());
	}

	@Override
	public void close() {
	}

}
