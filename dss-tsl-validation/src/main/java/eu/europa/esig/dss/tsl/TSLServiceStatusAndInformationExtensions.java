package eu.europa.esig.dss.tsl;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class TSLServiceStatusAndInformationExtensions extends BaseTimeDependent {

	private String status;
	private List<TSLConditionsForQualifiers> conditionsForQualifiers;
	private List<String> additionalServiceInfoUris;
	private Date expiredCertsRevocationInfo;

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public List<TSLConditionsForQualifiers> getConditionsForQualifiers() {
		return conditionsForQualifiers;
	}

	public void setConditionsForQualifiers(List<TSLConditionsForQualifiers> conditionsForQualifiers) {
		this.conditionsForQualifiers = conditionsForQualifiers;
	}

	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	public void setAdditionalServiceInfoUris(List<String> additionalServiceInfoUris) {
		this.additionalServiceInfoUris = additionalServiceInfoUris;
	}

	public void setExpiredCertsRevocationInfo(Date expiredCertsRevocationInfo) {
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

}
