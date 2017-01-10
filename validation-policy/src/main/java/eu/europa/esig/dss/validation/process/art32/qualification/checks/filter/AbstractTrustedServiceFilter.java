package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractTrustedServiceFilter implements TrustedServiceFilter {

	@Override
	public List<XmlTrustedServiceProvider> filter(List<XmlTrustedServiceProvider> tsps) {
		List<XmlTrustedServiceProvider> result = new ArrayList<XmlTrustedServiceProvider>();
		for (XmlTrustedServiceProvider tsp : tsps) {
			List<XmlTrustedService> services = getAcceptableServices(tsp.getTrustedServices());
			if (Utils.isCollectionNotEmpty(services)) {
				// replace trusted services with filter result
				tsp.setTrustedServices(services);
				result.add(tsp);
			}
		}
		return result;
	}

	abstract List<XmlTrustedService> getAcceptableServices(List<XmlTrustedService> originServices);

}
