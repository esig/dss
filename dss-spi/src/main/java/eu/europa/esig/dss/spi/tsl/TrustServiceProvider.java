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
package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.spi.tsl.builder.TrustServiceProviderBuilder;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class is a DTO representation for a trust service provider
 */
public class TrustServiceProvider implements Serializable {

	private static final long serialVersionUID = -2690449134555769275L;
	
	/*
	 * Key = lang
	 * 
	 * List = values / lang
	 */

	/** The map of names */
	private Map<String, List<String>> names;

	/** The map of trade names */
	private Map<String, List<String>> tradeNames;

	/** The list of registration identifiers */
	private List<String> registrationIdentifiers;

	/** The map of postal addresses */
	private Map<String, String> postalAddresses;

	/** The map of electronic addresses */
	private Map<String, List<String>> electronicAddresses;

	/** The map of information */
	private Map<String, String> information;

	/** The list of trust services */
	private List<TrustService> services;

	/** The territory (country) */
	private String territory;

	/**
	 * Empty constructor
	 *
	 * @deprecated since DSS 5.13. Use {@code new TrustServiceProviderBuilder.build()} method
	 */
	@Deprecated
	public TrustServiceProvider() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param builder {@link TrustServiceProviderBuilder}
	 */
	public TrustServiceProvider(TrustServiceProviderBuilder builder) {
		Objects.requireNonNull(builder, "TrustServiceProviderBuilder cannot be null!");
		this.names = builder.getNames();
		this.tradeNames = builder.getTradeNames();
		this.registrationIdentifiers = builder.getRegistrationIdentifiers();
		this.postalAddresses = builder.getPostalAddresses();
		this.electronicAddresses = builder.getElectronicAddresses();
		this.information = builder.getInformation();
		this.services = builder.getServices();
		this.territory = builder.getTerritory();
	}

	/**
	 * Gets a map of names
	 *
	 * @return a map of names
	 */
	public Map<String, List<String>> getNames() {
		return names;
	}

	/**
	 * Gets a map of trade names
	 *
	 * @return a map of trade names
	 */
	public Map<String, List<String>> getTradeNames() {
		return tradeNames;
	}

	/**
	 * Gets a list of registration identifiers
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getRegistrationIdentifiers() {
		return registrationIdentifiers;
	}

	/**
	 * Gets a map of postal addresses
	 *
	 * @return a map of postal addresses
	 */
	public Map<String, String> getPostalAddresses() {
		return postalAddresses;
	}

	/**
	 * Gets a map of electronic addresses
	 *
	 * @return a map of electronic addresses
	 */
	public Map<String, List<String>> getElectronicAddresses() {
		return electronicAddresses;
	}

	/**
	 * Gets a map of information
	 *
	 * @return a map of information
	 */
	public Map<String, String> getInformation() {
		return information;
	}

	/**
	 * Gets a list of trust services
	 *
	 * @return a list of {@link TrustService}s
	 */
	public List<TrustService> getServices() {
		return services;
	}

	/**
	 * Gets territory (country)
	 *
	 * @return {@link String}
	 */
	public String getTerritory() {
		return territory;
	}

}
