package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;

public class ServiceByDateFilter extends AbstractTrustedServiceFilter {

	private final Date date;

	public ServiceByDateFilter(Date date) {
		this.date = date;
	}

	@Override
	List<XmlTrustedService> getAcceptableServices(List<XmlTrustedService> originServices) {
		List<XmlTrustedService> result = new ArrayList<XmlTrustedService>();
		for (XmlTrustedService service : originServices) {
			Date startDate = service.getStartDate();
			Date endDate = service.getEndDate();
			if ((date.compareTo(startDate) >= 0) && (endDate == null || (date.compareTo(endDate) <= 0))) {
				result.add(service);
			}
		}
		return result;
	}

}
