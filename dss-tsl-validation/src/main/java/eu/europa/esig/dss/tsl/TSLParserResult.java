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

import java.util.Date;
import java.util.List;

/**
 * This class is a DTO result for TSLParser Callable
 *
 */
public class TSLParserResult {

	private int sequenceNumber;
	private int version;
	private String territory;
	private Date issueDate;
	private Date nextUpdateDate;
	private List<TSLPointer> pointers;
	private List<TSLServiceProvider> serviceProviders;
	private List<String> distributionPoints;
	private List<String> englishSchemeInformationURIs;

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(int sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	public int getVersion() {
		return version;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	public String getTerritory() {
		return territory;
	}

	public void setTerritory(String territory) {
		this.territory = territory;
	}

	public Date getIssueDate() {
		return issueDate;
	}

	public void setIssueDate(Date issueDate) {
		this.issueDate = issueDate;
	}

	public Date getNextUpdateDate() {
		return nextUpdateDate;
	}

	public void setNextUpdateDate(Date nextUpdateDate) {
		this.nextUpdateDate = nextUpdateDate;
	}

	public List<TSLPointer> getPointers() {
		return pointers;
	}

	public void setPointers(List<TSLPointer> pointers) {
		this.pointers = pointers;
	}

	public List<TSLServiceProvider> getServiceProviders() {
		return serviceProviders;
	}

	public void setServiceProviders(List<TSLServiceProvider> serviceProviders) {
		this.serviceProviders = serviceProviders;
	}

	public List<String> getDistributionPoints() {
		return distributionPoints;
	}

	public void setDistributionPoints(List<String> distributionPoints) {
		this.distributionPoints = distributionPoints;
	}

	public List<String> getEnglishSchemeInformationURIs() {
		return englishSchemeInformationURIs;
	}

	public void setEnglishSchemeInformationURIs(List<String> englishSchemeInformationURIs) {
		this.englishSchemeInformationURIs = englishSchemeInformationURIs;
	}

}
