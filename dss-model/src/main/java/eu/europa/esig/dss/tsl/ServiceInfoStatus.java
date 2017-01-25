package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent implements Serializable {

	private static final long serialVersionUID = 4258613511229825596L;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>
	 */
	private final String type;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private final String status;

	private final Map<String, List<Condition>> qualifiersAndConditions;
	private final List<String> additionalServiceInfoUris;
	private final Date expiredCertsRevocationInfo;

	public ServiceInfoStatus(String type, String status, Map<String, List<Condition>> qualifiersAndConditions, List<String> additionalServiceInfoUris,
			Date expiredCertsRevocationInfo, Date startDate, Date endDate) {
		super(startDate, endDate);
		this.type = type;
		this.status = status;
		this.qualifiersAndConditions = qualifiersAndConditions;
		this.additionalServiceInfoUris = additionalServiceInfoUris;
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public String getType() {
		return type;
	}

	public String getStatus() {
		return status;
	}

	public Map<String, List<Condition>> getQualifiersAndConditions() {
		return qualifiersAndConditions;
	}

	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

}
