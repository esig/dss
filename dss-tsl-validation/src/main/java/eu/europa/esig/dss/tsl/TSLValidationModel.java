package eu.europa.esig.dss.tsl;

import java.util.Date;
import java.util.List;

public class TSLValidationModel {

	private String url;
	private String sha1Url;
	private String filepath;
	private String sha1FileContent;

	private Date loadedDate;
	private Date issueDate;
	private Date nextUpdateDate;
	private int sequenceNumber;
	private String territory;
	private List<TSLPointer> pointers;
	private List<TSLServiceProvider> serviceProviders;
	private List<String> distributionPoints;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getSha1Url() {
		return sha1Url;
	}

	public void setSha1Url(String sha1Url) {
		this.sha1Url = sha1Url;
	}

	public String getFilepath() {
		return filepath;
	}

	public void setFilepath(String filepath) {
		this.filepath = filepath;
	}

	public String getSha1FileContent() {
		return sha1FileContent;
	}

	public void setSha1FileContent(String sha1FileContent) {
		this.sha1FileContent = sha1FileContent;
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

	public int getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(int sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

	public String getTerritory() {
		return territory;
	}

	public void setTerritory(String territory) {
		this.territory = territory;
	}

	public List<TSLPointer> getPointers() {
		return pointers;
	}

	public void setPointers(List<TSLPointer> pointers) {
		this.pointers = pointers;
	}

	public List<String> getDistributionPoints() {
		return distributionPoints;
	}

	public void setDistributionPoints(List<String> distributionPoints) {
		this.distributionPoints = distributionPoints;
	}

	public List<TSLServiceProvider> getServiceProviders() {
		return serviceProviders;
	}

	public void setServiceProviders(List<TSLServiceProvider> serviceProviders) {
		this.serviceProviders = serviceProviders;
	}

}
