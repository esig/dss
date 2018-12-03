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
package eu.europa.esig.dss.tsl;

import java.util.List;

/**
 * This class is a DTO representation for a TSL service provider
 */
public class TSLServiceProvider {

	private String name;
	private String tradeName;
	private String registrationIdentifier;
	private String postalAddress;
	private String electronicAddress;
	private List<TSLService> services;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getTradeName() {
		return tradeName;
	}

	public void setTradeName(String tradeName) {
		this.tradeName = tradeName;
	}

	public String getRegistrationIdentifier() {
		return registrationIdentifier;
	}

	public void setRegistrationIdentifier(String registrationIdentifier) {
		this.registrationIdentifier = registrationIdentifier;
	}

	public String getPostalAddress() {
		return postalAddress;
	}

	public void setPostalAddress(String postalAddress) {
		this.postalAddress = postalAddress;
	}

	public String getElectronicAddress() {
		return electronicAddress;
	}

	public void setElectronicAddress(String electronicAddress) {
		this.electronicAddress = electronicAddress;
	}

	public List<TSLService> getServices() {
		return services;
	}

	public void setServices(List<TSLService> services) {
		this.services = services;
	}

}
