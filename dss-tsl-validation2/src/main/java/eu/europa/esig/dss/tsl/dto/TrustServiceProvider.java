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

	public Map<String, List<String>> getNames() {
		return names;
	}

	public void setNames(Map<String, List<String>> names) {
		this.names = names;
	}

	public Map<String, List<String>> getTradeNames() {
		return tradeNames;
	}

	public void setTradeNames(Map<String, List<String>> tradeNames) {
		this.tradeNames = tradeNames;
	}

	public List<String> getRegistrationIdentifiers() {
		return registrationIdentifiers;
	}

	public void setRegistrationIdentifiers(List<String> registrationIdentifiers) {
		this.registrationIdentifiers = registrationIdentifiers;
	}

	public Map<String, String> getPostalAddresses() {
		return postalAddresses;
	}

	public void setPostalAddresses(Map<String, String> postalAddresses) {
		this.postalAddresses = postalAddresses;
	}

	public Map<String, List<String>> getElectronicAddresses() {
		return electronicAddresses;
	}

	public void setElectronicAddresses(Map<String, List<String>> electronicAddresses) {
		this.electronicAddresses = electronicAddresses;
	}

	public Map<String, String> getInformation() {
		return information;
	}

	public void setInformation(Map<String, String> information) {
		this.information = information;
	}

	public List<TrustService> getServices() {
		return services;
	}

	public void setServices(List<TrustService> services) {
		this.services = services;
	}

}
