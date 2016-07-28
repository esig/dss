package eu.europa.esig.dss.util;

import java.util.Date;

public class BaseTimeDependent implements TimeDependent {

	private Date startDate;
	private Date endDate;
	
	public BaseTimeDependent() {
		super();
	}

	public BaseTimeDependent( final Date startDate, final Date endDate ) {
		super();
		this.startDate = startDate;
		this.endDate = endDate;
	}
	
	@Override
	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate( final Date d ) {
		this.startDate = d;
	}
	
	@Override
	public Date getEndDate() {
		return endDate;
	}
	
	public void setEndDate( final Date d ) {
		this.endDate = d;
	}

}
