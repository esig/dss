package eu.europa.esig.dss.tsl;

import java.util.Date;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent {

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private String status;

	public ServiceInfoStatus(String status, Date startDate, Date endDate) {
		super( startDate, endDate );
		this.status = status;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}
