package eu.europa.esig.dss.tsl;

import java.util.Date;

public class TSLValidationSummary {

	private String country;
	private String tslUrl;
	private int sequenceNumber;
	private Date loadedDate;
	private Date issueDate;
	private Date nextUpdateDate;
	private String indication;
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

	public String getIndication() {
		return indication;
	}

	public void setIndication(String indication) {
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
