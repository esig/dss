package eu.europa.esig.dss.tsl.parsing;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.tsl.cache.CachedResult;

public abstract class AbstractParsingResult implements CachedResult {

	private int sequenceNumber;
	private int version;
	private String territory;
	private Date issueDate;
	private Date nextUpdateDate;
	private List<String> distributionPoints;
	
	AbstractParsingResult() {
	}
	
	AbstractParsingResult(AbstractParsingResult parsingResult) {
		this.sequenceNumber = parsingResult.sequenceNumber;
		this.version = parsingResult.version;
		this.territory = parsingResult.territory;
		this.issueDate = parsingResult.issueDate;
		this.nextUpdateDate = parsingResult.nextUpdateDate;
		if (parsingResult.distributionPoints != null) {
			this.distributionPoints = new ArrayList<String>(parsingResult.distributionPoints);
		}
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

	public List<String> getDistributionPoints() {
		return distributionPoints;
	}

	public void setDistributionPoints(List<String> distributionPoints) {
		this.distributionPoints = distributionPoints;
	}

}
