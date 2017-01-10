package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.Date;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;

public class ServiceByDateFilter extends AbstractTrustedServiceFilter {

	private final Date date;

	public ServiceByDateFilter(Date date) {
		this.date = date;
	}

	@Override
	boolean isAcceptable(XmlTrustedService service) {
		Date startDate = service.getStartDate();
		Date endDate = service.getEndDate();
		return ((date.compareTo(startDate) >= 0) && (endDate == null || (date.compareTo(endDate) <= 0)));
	}

}
