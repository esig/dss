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
package eu.europa.esig.dss.spi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;

/**
 * The default security provider
 */
public final class DSSSecurityProvider {

	private static final Logger LOG = LoggerFactory.getLogger(DSSSecurityProvider.class);

	private DSSSecurityProvider() {
		// empty
	}

	/** Provider */
	private static Provider securityProvider;

	/**
	 * Gets the provider
	 *
	 * @return {@link Provider}
	 */
	public static Provider getSecurityProvider() {
		if (securityProvider == null) {
			securityProvider = new BouncyCastleProvider();
			LOG.debug("DSSSecurityProvider initialized with {}", BouncyCastleProvider.class);
		}
		return securityProvider;
	}

	/**
	 * Gets the security provider name
	 *
	 * @return {@link String}
	 */
	public static String getSecurityProviderName() {
		return getSecurityProvider().getName();
	}

	/**
	 * Sets the security provider
	 *
	 * @param provider {@link Provider}
	 */
	public static void setSecurityProvider(Provider provider) {
		LOG.debug("DSSSecurityProvider initialized with {}", provider.getClass());
		DSSSecurityProvider.securityProvider = provider;
	}

}
