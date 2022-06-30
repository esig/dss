package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.enumerations.MRAEquivalenceContext;
import eu.europa.esig.dss.enumerations.MRAStatus;

import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class ServiceEquivalence {

	private String legalInfo;
	private MRAStatus status;
	private Date startDate;

	private Map<ServiceTypeASi, ServiceTypeASi> typeAsiEquivalence;
	private Map<List<String>, List<String>> statusEquivalence;
	private EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences;
	private Map<String, String> qualifierEquivalence;

	public String getLegalInfo() {
		return legalInfo;
	}

	public void setLegalInfo(String legalInfo) {
		this.legalInfo = legalInfo;
	}

	public MRAStatus getStatus() {
		return status;
	}

	public void setStatus(MRAStatus status) {
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

	public EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> getCertificateContentEquivalences() {
		return certificateContentEquivalences;
	}

	public void setCertificateContentEquivalences(EnumMap<MRAEquivalenceContext, CertificateContentEquivalence> certificateContentEquivalences) {
		this.certificateContentEquivalences = certificateContentEquivalences;
	}

	public Map<String, String> getQualifierEquivalence() {
		return qualifierEquivalence;
	}

	public void setQualifierEquivalence(Map<String, String> qualifierEquivalence) {
		this.qualifierEquivalence = qualifierEquivalence;
	}

}
