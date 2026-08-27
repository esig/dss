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
package eu.europa.esig.dss.spi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import java.util.Objects;

/**
 * The default security provider.
 * <p>
 * In order to initialize the providers within the system, please call the {@code #initSystemProviders} method.
 * NOTE: once {@code #initSystemProviders} method called, all the primary and alternative security providers
 *       will be added within the system's Security providers list.
 *       They won't be removed automatically, if the security providers configuration is changed within the class.
 */
public final class DSSSecurityProvider {

	private static final Logger LOG = LoggerFactory.getLogger(DSSSecurityProvider.class);

	/**
	 * Empty constructor
	 */
	private DSSSecurityProvider() {
		// empty
	}

	/** Primary security provider */
	private static Provider securityProvider;

	/** Array of alternative security providers (optional) */
	private static Provider[] alternativeSecurityProviders;

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
		assertProvidersNotNull(provider);
		DSSSecurityProvider.securityProvider = provider;
		LOG.debug("DSSSecurityProvider initialized with {}", provider.getClass());
	}

	/**
	 * Sets the security provider by the given Provider name
	 *
	 * @param providerName {@link String}
	 * @throws SecurityException if unable to instantiate the Provider by the given name
	 */
	public static void setSecurityProvider(String providerName) throws SecurityException {
		assertProviderNamesNotNull(providerName);
		DSSSecurityProvider.securityProvider = getProvider(providerName);
		LOG.debug("DSSSecurityProvider initialized with {}", providerName);
	}

	/**
	 * Gets an array of alternative security providers
	 *
	 * @return an array of {@link Provider}s
	 */
	public static Provider[] getAlternativeSecurityProviders() {
		if (alternativeSecurityProviders == null) {
			alternativeSecurityProviders = new Provider[] {};
		}
		return alternativeSecurityProviders;
	}

	/**
	 * Gets an array of alternative security provider names
	 *
	 * @return an array of {@link String}s
	 */
	public static String[] getAlternativeSecurityProviderNames() {
		if (alternativeSecurityProviders == null || alternativeSecurityProviders.length == 0) {
			return new String[] {};
		}
		final String[] providerNames = new String[alternativeSecurityProviders.length];
		for (int i = 0; i < alternativeSecurityProviders.length; i++) {
			providerNames[i] = alternativeSecurityProviders[i].getName();
		}
		return providerNames;
	}

	/**
	 * Sets alternative security providers.
	 * In case the primary security providers fails on operation, DSS will load the alternative
	 * security providers in provided order, until the first provider succeeding the operation
	 *
	 * @param alternativeSecurityProviders array of {@link Provider}s
	 */
	public static void setAlternativeSecurityProviders(Provider... alternativeSecurityProviders) {
		assertProvidersNotNull(alternativeSecurityProviders);
		DSSSecurityProvider.alternativeSecurityProviders = alternativeSecurityProviders;
	}

	/**
	 * Sets alternative security providers by their names.
	 * In case the primary security providers fails on operation, DSS will load the alternative
	 * security providers in provided order, until the first provider succeeding the operation
	 *
	 * @param alternativeSecurityProviderNames array of {@link String}s
	 * @throws SecurityException if unable to instantiate the Provider by the given name
	 */
	public static void setAlternativeSecurityProviders(String... alternativeSecurityProviderNames) throws SecurityException {
		assertProviderNamesNotNull(alternativeSecurityProviderNames);
		if (alternativeSecurityProviderNames.length == 0) {
			return;
		}
		final Provider[] providerArray = new Provider[alternativeSecurityProviderNames.length];
		for (int i = 0; i < providerArray.length; i++) {
			providerArray[i] = getProvider(alternativeSecurityProviderNames[i]);
		}
		DSSSecurityProvider.alternativeSecurityProviders = providerArray;
	}

	private static void assertProvidersNotNull(Provider... providers) {
		Objects.requireNonNull(providers, "Array of providers cannot be null!");
		for (Provider provider : providers) {
			Objects.requireNonNull(provider, "Provider cannot be null!");
		}
	}

	private static void assertProviderNamesNotNull(String... providerNames) {
		Objects.requireNonNull(providerNames, "Array of provider names cannot be null!");
		for (String providerName : providerNames) {
			Objects.requireNonNull(providerName, "Provider name cannot be null!");
		}
	}

	private static Provider getProvider(String providerName) throws SecurityException {
		try {
			Provider provider = Security.getProvider(providerName);
			if (provider == null) {
				throw new IllegalArgumentException(String.format(
						"Unable to instantiate security Provider for name '%s'! The implementation is not found.", providerName));
			}
			return provider;

		} catch (Exception e) {
			throw new SecurityException(String.format(
					"An error occurred on security Provider initialization : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method adds the configured within the {@code java.security.Security} providers' list.
	 * This method shall be called before the use of the security providers is required by the code.
	 * NOTE: once called, all the primary and alternative security providers will be added within
	 *       the system's Security providers list. They won't be removed automatically,
	 *       if the security providers configuration is changed within the class.
	 */
	public static void initSystemProviders() {
		Security.addProvider(getSecurityProvider());
		Provider[] securityProviders = getAlternativeSecurityProviders();
		if (securityProviders != null && securityProviders.length != 0) {
			for (Provider provider : securityProviders) {
				Security.addProvider(provider);
			}
		}
	}

}
