package eu.europa.esig.dss.tsl;

import java.util.Date;
import java.util.List;

public class TSLParserResult {

	private int sequenceNumber;
	private String territory;
	private Date issueDate;
	private Date nextUpdateDate;
	private List<TSLPointer> pointers;
	private List<TSLServiceProvider> serviceProviders;
	private List<String> distributionPoints;

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

}
