package eu.europa.esig.dss.tsl;

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
