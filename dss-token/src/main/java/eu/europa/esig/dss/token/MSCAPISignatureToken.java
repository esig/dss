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

import java.io.IOException;
import java.security.*;
import java.security.KeyStore.PasswordProtection;

/**
 * Class holding all MS CAPI API access logic.
 *
 */
public class MSCAPISignatureToken extends AbstractKeyStoreTokenConnection {
	private static final String SUN_MSCAPI = "SunMSCAPI";
	/**
	 * Default constructor
	 */
	public MSCAPISignatureToken() {
		// empty
	}

	@Override
	protected KeyStore getKeyStore() throws DSSException {
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);
		} catch (IOException | GeneralSecurityException e) {
			throw new DSSException("Unable to load MS CAPI keystore", e);
		}
		return keyStore;
	}

	@Override
	protected PasswordProtection getKeyProtectionParameter() {
		return new PasswordProtection("nimp".toCharArray());
	}

	@Override
	public void close() {
		// nothing to close
	}

	@Override
	protected Signature getSignatureInstance(final String javaSignatureAlgorithm) throws NoSuchAlgorithmException {
		try {
			return Signature.getInstance(javaSignatureAlgorithm, SUN_MSCAPI);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// Fallback to default behavior (e.g. if algorithm not supported by SunMSCAPI or
			// provider not available)
			return super.getSignatureInstance(javaSignatureAlgorithm);
		}
	}

}
