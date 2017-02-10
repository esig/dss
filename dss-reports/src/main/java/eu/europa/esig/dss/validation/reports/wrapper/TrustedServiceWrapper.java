package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.Date;
import java.util.List;

public class TrustedServiceWrapper {

	private String countryCode;
	private String status;
	private String type;
	private Date startDate;
	private Date endDate;
	private List<String> capturedQualifiers;
	private List<String> additionalServiceInfos;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	public List<String> getCapturedQualifiers() {
		return capturedQualifiers;
	}

	public void setCapturedQualifiers(List<String> capturedQualifiers) {
		this.capturedQualifiers = capturedQualifiers;
	}

	public List<String> getAdditionalServiceInfos() {
		return additionalServiceInfos;
	}

	public void setAdditionalServiceInfos(List<String> additionalServiceInfos) {
		this.additionalServiceInfos = additionalServiceInfos;
	}

}
