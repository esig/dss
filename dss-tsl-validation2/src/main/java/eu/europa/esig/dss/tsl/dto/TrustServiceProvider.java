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
package eu.europa.esig.dss.tsl.dto;

import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.tsl.dto.builder.TrustServiceProviderBuilder;

/**
 * This class is a DTO representation for a trust service provider
 */
public class TrustServiceProvider {

	/**
	 * Key = lang
	 * 
	 * List = values / lang
	 */
	private Map<String, List<String>> names;
	private Map<String, List<String>> tradeNames;
	private List<String> registrationIdentifiers;
	private Map<String, String> postalAddresses;
	private Map<String, List<String>> electronicAddresses;
	private Map<String, String> information;
	private List<TrustService> services;
	
	public TrustServiceProvider() {
	}
	
	public TrustServiceProvider(TrustServiceProviderBuilder builder) {
		this.names = builder.getNames();
		this.tradeNames = builder.getTradeNames();
		this.registrationIdentifiers = builder.getRegistrationIdentifiers();
		this.postalAddresses = builder.getPostalAddresses();
		this.electronicAddresses = builder.getElectronicAddresses();
		this.information = builder.getInformation();
		this.services = builder.getServices();
	}

	public Map<String, List<String>> getNames() {
		return names;
	}

	public Map<String, List<String>> getTradeNames() {
		return tradeNames;
	}

	public List<String> getRegistrationIdentifiers() {
		return registrationIdentifiers;
	}

	public Map<String, String> getPostalAddresses() {
		return postalAddresses;
	}

	public Map<String, List<String>> getElectronicAddresses() {
		return electronicAddresses;
	}

	public Map<String, String> getInformation() {
		return information;
	}

	public List<TrustService> getServices() {
		return services;
	}

}
