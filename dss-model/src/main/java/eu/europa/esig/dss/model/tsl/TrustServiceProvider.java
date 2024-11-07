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
package eu.europa.esig.dss.model.tsl;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

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
	 * Default constructor
	 *
	 */
	public TrustServiceProvider() {
		// empty
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
	 * Sets a map of names
	 *
	 * @param names a map of names
	 */
	public void setNames(Map<String, List<String>> names) {
		this.names = names;
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
	 * Sets a map of trade names
	 *
	 * @param tradeNames a map of trade names
	 */
	public void setTradeNames(Map<String, List<String>> tradeNames) {
		this.tradeNames = tradeNames;
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
	 * Sets a list of registration identifiers
	 *
	 * @param registrationIdentifiers a list of registration identifiers
	 */
	public void setRegistrationIdentifiers(List<String> registrationIdentifiers) {
		this.registrationIdentifiers = registrationIdentifiers;
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
	 * Sets a map of postal addresses
	 *
	 * @param postalAddresses a map of postal addresses
	 */
	public void setPostalAddresses(Map<String, String> postalAddresses) {
		this.postalAddresses = postalAddresses;
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
	 * Sets a map of electronic addresses
	 *
	 * @param electronicAddresses a map of electronic addresses
	 */
	public void setElectronicAddresses(Map<String, List<String>> electronicAddresses) {
		this.electronicAddresses = electronicAddresses;
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
	 * Sets a map of information
	 *
	 * @param information a map of information
	 */
	public void setInformation(Map<String, String> information) {
		this.information = information;
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
	 * Sets a list of trust services
	 *
	 * @param services a list of trust services
	 */
	public void setServices(List<TrustService> services) {
		this.services = services;
	}

	/**
	 * Gets territory (country)
	 *
	 * @return {@link String}
	 */
	public String getTerritory() {
		return territory;
	}

	/**
	 * Sets territory (country)
	 * @param territory {@link String}
	 */
	public void setTerritory(String territory) {
		this.territory = territory;
	}

}
