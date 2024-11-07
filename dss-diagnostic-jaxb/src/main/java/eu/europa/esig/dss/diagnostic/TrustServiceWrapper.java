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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlQualifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Wraps an extracted information from a Trusted Service
 *
 */
public class TrustServiceWrapper {

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
	private List<XmlQualifier> capturedQualifiers;

	/** Additional service informations */
	private List<String> additionalServiceInfos;

	/** Defines whether MRA has been applied for this particular Trusted Service */
	private Boolean enactedMRA;

	/** The name of the Trust Service defined the Mutual Recognition Agreement equivalence scheme */
	private String mraTrustServiceLegalIdentifier;

	/** The date when the status for the current MRA Trust Service equivalence has been started */
	private Date mraTrustServiceEquivalenceStatusStartingTime;

	/** The date when the status for the current MRA Trust Service equivalence has been ended (if applicable) */
	private Date mraTrustServiceEquivalenceStatusEndingTime;

	/** Original third-country status before applied MRA */
	private String originalTCStatus;

	/** Original third-country type before applied MRA */
	private String originalTCType;

	/** Original third-country captured qualifiers before applied MRA */
	private List<XmlQualifier> originalCapturedQualifiers;

	/** Original third-country captured qualifiers before applied MRA */
	private List<String> originalTCAdditionalServiceInfos;

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
	 * Gets TrustService start validity date
	 *
	 * @return {@link Date}
	 */
	public Date getStartDate() {
		return startDate;
	}

	/**
	 * Sets TrustService start validity date
	 *
	 * @param startDate {@link Date}
	 */
	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	/**
	 * Gets TrustService end validity date
	 *
	 * @return {@link Date}
	 */
	public Date getEndDate() {
		return endDate;
	}

	/**
	 * Sets TrustService end validity date
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
	public List<XmlQualifier> getCapturedQualifiers() {
		return capturedQualifiers;
	}

	/**
	 * Gets captured qualifiers
	 *
	 * @return list of {@link String}s
	 */
	public List<String> getCapturedQualifierUris() {
		if (capturedQualifiers != null) {
			return capturedQualifiers.stream().map(XmlQualifier::getValue).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * Sets captured qualifiers
	 *
	 * @param capturedQualifiers list of {@link String}s
	 */
	public void setCapturedQualifiers(List<XmlQualifier> capturedQualifiers) {
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

	/**
	 * Gets whether MRA has been enacted for this Trusted Service
	 *
	 * @return {@link Boolean}
	 */
	public boolean isEnactedMRA() {
		return enactedMRA != null && enactedMRA;
	}

	/**
	 * Sets whether MRA has been enacted for this Trusted Service
	 *
	 * @param enactedMRA {@link Boolean}
	 */
	public void setEnactedMRA(Boolean enactedMRA) {
		this.enactedMRA = enactedMRA;
	}

	/**
	 * Gets the Trust Service Legal Identifier matching the Trust Service defined within MRA
	 *
	 * @return {@link String}
	 */
	public String getMraTrustServiceLegalIdentifier() {
		return mraTrustServiceLegalIdentifier;
	}

	/**
	 * Sets the Trust Service Legal Identifier matching the Trust Service defined within MRA
	 *
	 * @param mraTrustServiceLegalIdentifier {@link String}
	 */
	public void setMraTrustServiceLegalIdentifier(String mraTrustServiceLegalIdentifier) {
		this.mraTrustServiceLegalIdentifier = mraTrustServiceLegalIdentifier;
	}

	/**
	 * Gets the Trust Service equivalence status starting time defined within MRA
	 *
	 * @return {@link Date}
	 */
	public Date getMraTrustServiceEquivalenceStatusStartingTime() {
		return mraTrustServiceEquivalenceStatusStartingTime;
	}

	/**
	 * Sets the Trust Service equivalence status starting time defined within MRA
	 *
	 * @param mraTrustServiceEquivalenceStatusStartingTime {@link Date}
	 */
	public void setMraTrustServiceEquivalenceStatusStartingTime(Date mraTrustServiceEquivalenceStatusStartingTime) {
		this.mraTrustServiceEquivalenceStatusStartingTime = mraTrustServiceEquivalenceStatusStartingTime;
	}

	/**
	 * Gets the Trust Service equivalence status ending time defined within MRA
	 *
	 * @return {@link Date}
	 */
	public Date getMraTrustServiceEquivalenceStatusEndingTime() {
		return mraTrustServiceEquivalenceStatusEndingTime;
	}

	/**
	 * Sets the Trust Service equivalence status ending time defined within MRA
	 *
	 * @param mraTrustServiceEquivalenceStatusEndingTime {@link Date}
	 */
	public void setMraTrustServiceEquivalenceStatusEndingTime(Date mraTrustServiceEquivalenceStatusEndingTime) {
		this.mraTrustServiceEquivalenceStatusEndingTime = mraTrustServiceEquivalenceStatusEndingTime;
	}

	/**
	 * Gets original third-country status defined within Trusted List (before applied MRA)
	 *
	 * @return {@link String}
	 */
	public String getOriginalTCStatus() {
		return originalTCStatus;
	}

	/**
	 * Sets original third-country status defined within Trusted List (before applied MRA)
	 *
	 * @param originalTCStatus {@link String}
	 */
	public void setOriginalTCStatus(String originalTCStatus) {
		this.originalTCStatus = originalTCStatus;
	}

	/**
	 * Gets original third-country type defined within Trusted List (before applied MRA)
	 *
	 * @return {@link String}
	 */
	public String getOriginalTCType() {
		return originalTCType;
	}

	/**
	 * Sets original third-country type defined within Trusted List (before applied MRA)
	 *
	 * @param originalTCType {@link String}
	 */
	public void setOriginalTCType(String originalTCType) {
		this.originalTCType = originalTCType;
	}

	/**
	 * Gets original third-country captured qualifiers defined within Trusted List (before applied MRA)
	 *
	 * @return a list of {@link XmlQualifier}s
	 */
	public List<XmlQualifier> getOriginalCapturedQualifiers() {
		return originalCapturedQualifiers;
	}

	/**
	 * Gets original third-country captured qualifier URIs defined within Trusted List (before applied MRA)
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOriginalCapturedQualifierUris() {
		if (originalCapturedQualifiers != null) {
			return originalCapturedQualifiers.stream().map(XmlQualifier::getValue).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * Sets original third-country captured qualifiers defined within Trusted List (before applied MRA)
	 *
	 * @param originalCapturedQualifiers a list of {@link XmlQualifier}s
	 */
	public void setOriginalCapturedQualifiers(List<XmlQualifier> originalCapturedQualifiers) {
		this.originalCapturedQualifiers = originalCapturedQualifiers;
	}

	/**
	 * Gets original third-country additional service informations defined within Trusted List (before applied MRA)
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOriginalTCAdditionalServiceInfos() {
		return originalTCAdditionalServiceInfos;
	}

	/**
	 * Sets original third-country additional service informations defined within Trusted List (before applied MRA)
	 *
	 * @param originalTCAdditionalServiceInfos a list of {@link String}s
	 */
	public void setOriginalTCAdditionalServiceInfos(List<String> originalTCAdditionalServiceInfos) {
		this.originalTCAdditionalServiceInfos = originalTCAdditionalServiceInfos;
	}

}
