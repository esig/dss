package eu.europa.esig.dss.spi.tsl;

import java.util.Date;
import java.util.List;
import java.util.Map;

public class ServiceEquivalence {

	private String legalInfo;
	private String status;
	private Date startDate;

	private Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence;
	private Map<List<String>, List<String>> statusEquivalence;
	private Map<Condition, QCStatementOids> certificateContentEquivalence;
	private Map<String, String> qualifierEquivalence;

	public String getLegalInfo() {
		return legalInfo;
	}

	public void setLegalInfo(String legalInfo) {
		this.legalInfo = legalInfo;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Map<ServiceTypeASi, ServiceTypeASi> getTypeAsiEquivalence() {
		return typeAsiEquivalence;
	}

	public void setTypeAsiEquivalence(Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence) {
		this.typeAsiEquivalence = typeAsiEquivalence;
	}

	public Map<List<String>, List<String>> getStatusEquivalence() {
		return statusEquivalence;
	}

	public void setStatusEquivalence(Map<List<String>, List<String>> statusEquivalence) {
		this.statusEquivalence = statusEquivalence;
	}

	public Map<Condition, QCStatementOids> getCertificateContentEquivalence() {
		return certificateContentEquivalence;
	}

	public void setCertificateContentEquivalence(Map<Condition, QCStatementOids> certificateContentEquivalence) {
		this.certificateContentEquivalence = certificateContentEquivalence;
	}

	public Map<String, String> getQualifierEquivalence() {
		return qualifierEquivalence;
	}

	public void setQualifierEquivalence(Map<String, String> qualifierEquivalence) {
		this.qualifierEquivalence = qualifierEquivalence;
	}

}
