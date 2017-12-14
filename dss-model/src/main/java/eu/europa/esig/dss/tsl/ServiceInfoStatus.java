package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent implements Serializable {

	private static final long serialVersionUID = 4258613511229825596L;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>
	 * }
	 * </pre>
	 */
	private final String type;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 * }
	 * </pre>
	 */
	private final String status;

	private final Map<String, List<Condition>> qualifiersAndConditions;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceInformationExtensions><tsl:Extension><tsl:AdditionalServiceInformation>
	 * }
	 * </pre>
	 */
	private final List<String> additionalServiceInfoUris;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceSupplyPoints>
	 * }
	 * </pre>
	 */
	private final List<String> serviceSupplyPoints;

	/**
	 * <pre>
	 * {@code
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceInformationExtensions><tsl:Extension><tsl:ExpiredCertsRevocationInfo>
	 * }
	 * </pre>
	 */
	private final Date expiredCertsRevocationInfo;

	public ServiceInfoStatus(String type, String status, Map<String, List<Condition>> qualifiersAndConditions, List<String> additionalServiceInfoUris,
			List<String> serviceSupplyPoints, Date expiredCertsRevocationInfo, Date startDate, Date endDate) {
		super(startDate, endDate);
		this.type = type;
		this.status = status;
		this.qualifiersAndConditions = qualifiersAndConditions;
		this.additionalServiceInfoUris = additionalServiceInfoUris;
		this.serviceSupplyPoints = serviceSupplyPoints;
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	/**
	 * Returns the ServiceTypeIdentifier
	 * 
	 * @return the ServiceTypeIdentifier
	 */
	public String getType() {
		return type;
	}

	/**
	 * Returns the ServiceStatus
	 * 
	 * @return the ServiceStatus
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Returns a Map of qualifiers with its conditions
	 * 
	 * @return a Map of qualifiers with its conditions
	 */
	public Map<String, List<Condition>> getQualifiersAndConditions() {
		return qualifiersAndConditions;
	}

	/**
	 * Returns a List of AdditionalServiceInformation
	 * 
	 * @return the list of AdditionalServiceInformation
	 */
	public List<String> getAdditionalServiceInfoUris() {
		return additionalServiceInfoUris;
	}

	/**
	 * Returns a list of ServiceSupplyPoints
	 * 
	 * @return the list of ServiceSupplyPoints
	 */
	public List<String> getServiceSupplyPoints() {
		return serviceSupplyPoints;
	}

	/**
	 * Returns the ExpiredCertsRevocationInfo's date
	 * 
	 * @return the date ExpiredCertsRevocationInfo
	 */
	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

}
