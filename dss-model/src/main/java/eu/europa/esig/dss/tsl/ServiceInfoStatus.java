package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.Date;

public class ServiceInfoStatus implements Serializable{

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private String status;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:StatusStartingTime>
	 */
	private Date startDate;

	/**
	 * The start date of the previous service history or null if current service
	 */
	private Date endDate;

	public ServiceInfoStatus(String status, Date startDate, Date endDate) {
		this.status = status;
		this.startDate = startDate;
		this.endDate = endDate;
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

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

}
