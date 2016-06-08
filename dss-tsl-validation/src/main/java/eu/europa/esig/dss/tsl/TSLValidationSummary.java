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

import eu.europa.esig.dss.validation.policy.rules.Indication;

/**
 * This class is a DTO representation for an analysis summary.
 */
public class TSLValidationSummary {

	private String country;
	private String tslUrl;
	private int sequenceNumber;
	private Date loadedDate;
	private Date issueDate;
	private Date nextUpdateDate;
	private Indication indication;
	private int nbServiceProviders;
	private int nbServices;
	private int nbCertificatesAndX500Principals;

	public String getCountry() {
		return country;
	}

	public void setCountry(String country) {
		this.country = country;
	}

	public String getTslUrl() {
		return tslUrl;
	}

	public void setTslUrl(String tslUrl) {
		this.tslUrl = tslUrl;
	}

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(int sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	public Date getLoadedDate() {
		return loadedDate;
	}

	public void setLoadedDate(Date loadedDate) {
		this.loadedDate = loadedDate;
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

	public Indication getIndication() {
		return indication;
	}

	public void setIndication(Indication indication) {
		this.indication = indication;
	}

	public int getNbServiceProviders() {
		return nbServiceProviders;
	}

	public void setNbServiceProviders(int nbServiceProviders) {
		this.nbServiceProviders = nbServiceProviders;
	}

	public int getNbServices() {
		return nbServices;
	}

	public void setNbServices(int nbServices) {
		this.nbServices = nbServices;
	}

	public int getNbCertificatesAndX500Principals() {
		return nbCertificatesAndX500Principals;
	}

	public void setNbCertificatesAndX500Principals(int nbCertificatesAndX500Principals) {
		this.nbCertificatesAndX500Principals = nbCertificatesAndX500Principals;
	}

}
