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

import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;

import java.util.Date;
import java.util.List;

/**
 * Wraps an extracted information from a Trusted Service
 *
 */
public class TrustedServiceWrapper {

	/** Corresponding Trusted List */
	private XmlTrustedList trustedList;

	/** Corresponding List of Trusted Lists */
	private XmlTrustedList lotl;

	/** Trust Service Provider names */
	private List<String> tspNames;

	/** Trust Service Provider trade names */
	private List<String> tspTradeNames;

	/** Related certificate */
	private CertificateWrapper serviceDigitalIdentifier;

	/** Trusted service names */
	private List<String> serviceNames;

	/** Country code */
	private String countryCode;

	/** Status */
	private String status;

	/** Type */
	private String type;

	/** Start date of validity */
	private Date startDate;

	/** End date of validity */
	private Date endDate;

	/** Captured qualifiers */
	private List<String> capturedQualifiers;

	/** Additional service informations */
	private List<String> additionalServiceInfos;
	private Boolean enactedMRA;

	/**
	 * Gets corresponding Trusted List
	 *
	 * @return {@link XmlTrustedList}
	 */
	public XmlTrustedList getTrustedList() {
		return trustedList;
	}

	/**
	 * Sets corresponding Trusted List
	 *
	 * @param trustedList {@link XmlTrustedList}
	 */
	public void setTrustedList(XmlTrustedList trustedList) {
		this.trustedList = trustedList;
	}

	/**
	 * Gets corresponding List of Trusted Lists
	 *
	 * @return {@link XmlTrustedList}
	 */
	public XmlTrustedList getListOfTrustedLists() {
		return lotl;
	}

	/**
	 * Sets corresponding List of Trusted Lists
	 *
	 * @param lotl {@link XmlTrustedList}
	 */
	public void setListOfTrustedLists(XmlTrustedList lotl) {
		this.lotl = lotl;
	}

	/**
	 * Gets Trusted Service Provider names
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getTspNames() {
		return tspNames;
	}

	/**
	 * Sets Trusted Service Provider names
	 *
	 * @param tspNames list of {@link String}s
	 */
	public void setTspNames(List<String> tspNames) {
		this.tspNames = tspNames;
	}

	/**
	 * Gets Trusted Service Provider trade names
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getTspTradeNames() {
		return tspTradeNames;
	}

	/**
	 * Sets Trusted Service Provider trade names
	 *
	 * @param tspTradeNames list of {@link String}s
	 */
	public void setTspTradeNames(List<String> tspTradeNames) {
		this.tspTradeNames = tspTradeNames;
	}

	/**
	 * Gets Service Digital Identifier Certificate
	 *
	 * @return {@link CertificateWrapper}
	 */
	public CertificateWrapper getServiceDigitalIdentifier() {
		return serviceDigitalIdentifier;
	}

	/**
	 * Sets Service Digital Identifier Certificate
	 *
	 * @param serviceDigitalIdentifier {@link CertificateWrapper}
	 */
	public void setServiceDigitalIdentifier(CertificateWrapper serviceDigitalIdentifier) {
		this.serviceDigitalIdentifier = serviceDigitalIdentifier;
	}

	/**
	 * Gets service names
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getServiceNames() {
		return serviceNames;
	}

	/**
	 * Sets service names
	 *
	 * @param serviceNames list of {@link String}s
	 */
	public void setServiceNames(List<String> serviceNames) {
		this.serviceNames = serviceNames;
	}

	/**
	 * Gets country code
	 *
	 * @return {@link String}
	 */
	public String getCountryCode() {
		return countryCode;
	}

	/**
	 * Sets country code
	 *
	 * @param countryCode {@link String}
	 */
	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	/**
	 * Gets status
	 *
	 * @return {@link String}
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Sets status
	 *
	 * @param status {@link String}
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * Gets type
	 *
	 * @return {@link String}
	 */
	public String getType() {
		return type;
	}

	/**
	 * Sets type
	 *
	 * @param type {@link String}
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * Gets TrustedService start validity date
	 *
	 * @return {@link Date}
	 */
	public Date getStartDate() {
		return startDate;
	}

	/**
	 * Sets TrustedService start validity date
	 *
	 * @param startDate {@link Date}
	 */
	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	/**
	 * Gets TrustedService end validity date
	 *
	 * @return {@link Date}
	 */
	public Date getEndDate() {
		return endDate;
	}

	/**
	 * Sets TrustedService end validity date
	 *
	 * @param endDate {@link Date}
	 */
	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	/**
	 * Gets captured qualifiers
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getCapturedQualifiers() {
		return capturedQualifiers;
	}

	/**
	 * Sets captured qualifiers
	 *
	 * @param capturedQualifiers list of {@link String}s
	 */
	public void setCapturedQualifiers(List<String> capturedQualifiers) {
		this.capturedQualifiers = capturedQualifiers;
	}

	/**
	 * Gets additional service informations
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getAdditionalServiceInfos() {
		return additionalServiceInfos;
	}

	/**
	 * Sets additional service informations
	 *
	 * @param additionalServiceInfos list of {@link String}s
	 */
	public void setAdditionalServiceInfos(List<String> additionalServiceInfos) {
		this.additionalServiceInfos = additionalServiceInfos;
	}

	public void setEnactedMRA(Boolean enactedMRA) {
		this.enactedMRA = enactedMRA;
	}

	public Boolean getEnactedMRA() {
		return enactedMRA;
	}

}
