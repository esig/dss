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

import java.util.Date;

public class TLInfo {

	private String countryCode;
	private String url;
	private int sequenceNumber;
	private int version;
	private Date issueDate;
	private Date lastLoading;
	private Date nextUpdate;
	private boolean lotl;
	private boolean wellSigned; // Indication = VALID

	private int nbServiceProviders;
	private int nbServices;
	private int nbCertificates;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

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

	public Date getIssueDate() {
		return issueDate;
	}

	public void setIssueDate(Date issueDate) {
		this.issueDate = issueDate;
	}

	public Date getNextUpdate() {
		return nextUpdate;
	}

	public void setNextUpdate(Date nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	public Date getLastLoading() {
		return lastLoading;
	}

	public void setLastLoading(Date lastLoading) {
		this.lastLoading = lastLoading;
	}

	public boolean isLotl() {
		return lotl;
	}

	public void setLotl(boolean lotl) {
		this.lotl = lotl;
	}

	public boolean isWellSigned() {
		return wellSigned;
	}

	public void setWellSigned(boolean wellSigned) {
		this.wellSigned = wellSigned;
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

	public int getNbCertificates() {
		return nbCertificates;
	}

	public void setNbCertificates(int nbCertificates) {
		this.nbCertificates = nbCertificates;
	}

}
