package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import java.util.Date;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class ServiceByDateFilter extends AbstractTrustedServiceFilter {

	private final Date date;

	public ServiceByDateFilter(Date date) {
		this.date = date;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		Date startDate = service.getStartDate();
		Date endDate = service.getEndDate();

		if (date == null) { // possible in case of null signing time
			return false;
		}

		boolean afterStartRange = (startDate != null && (date.compareTo(startDate) >= 0));
		boolean beforeEndRange = (endDate == null || (date.compareTo(endDate) <= 0)); // end date can be null (in case
																						// of current status)

		return afterStartRange && beforeEndRange;
	}

}
