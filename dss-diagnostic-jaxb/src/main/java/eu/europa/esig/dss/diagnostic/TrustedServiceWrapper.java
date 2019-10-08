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
package eu.europa.esig.dss.diagnostic;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;

public class TrustedServiceWrapper {

	private XmlTrustedList trustedList;
	private XmlTrustedList lotl;
	private List<String> tspNames;
	private CertificateWrapper serviceDigitalIdentifier;
	private List<String> serviceNames;
	private String countryCode;
	private String status;
	private String type;
	private Date startDate;
	private Date endDate;
	private List<String> capturedQualifiers;
	private List<String> additionalServiceInfos;

	public XmlTrustedList getTrustedList() {
		return trustedList;
	}

	public void setTrustedList(XmlTrustedList trustedList) {
		this.trustedList = trustedList;
	}

	public XmlTrustedList getListOfTrustedLists() {
		return lotl;
	}

	public void setListOfTrustedLists(XmlTrustedList lotl) {
		this.lotl = lotl;
	}

	public List<String> getTspNames() {
		return tspNames;
	}

	public void setTspNames(List<String> tspNames) {
		this.tspNames = tspNames;
	}

	public CertificateWrapper getServiceDigitalIdentifier() {
		return serviceDigitalIdentifier;
	}

	public void setServiceDigitalIdentifier(CertificateWrapper serviceDigitalIdentifier) {
		this.serviceDigitalIdentifier = serviceDigitalIdentifier;
	}

	public List<String> getServiceNames() {
		return serviceNames;
	}

	public void setServiceNames(List<String> serviceNames) {
		this.serviceNames = serviceNames;
	}

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	public List<String> getCapturedQualifiers() {
		return capturedQualifiers;
	}

	public void setCapturedQualifiers(List<String> capturedQualifiers) {
		this.capturedQualifiers = capturedQualifiers;
	}

	public List<String> getAdditionalServiceInfos() {
		return additionalServiceInfos;
	}

	public void setAdditionalServiceInfos(List<String> additionalServiceInfos) {
		this.additionalServiceInfos = additionalServiceInfos;
	}

}
