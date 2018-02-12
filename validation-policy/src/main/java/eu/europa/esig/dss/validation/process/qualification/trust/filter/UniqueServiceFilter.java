package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class UniqueServiceFilter implements TrustedServiceFilter {

	private static final Logger LOG = LoggerFactory.getLogger(UniqueServiceFilter.class);

	private final CertificateWrapper rootCert;

	public UniqueServiceFilter(CertificateWrapper rootCert) {
		this.rootCert = rootCert;
	}

	@Override
	public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices) {
		TrustedServiceWrapper selectedTrustedService = null;

		if (rootCert != null) {
			if (Utils.collectionSize(trustedServices) == 1) {
				selectedTrustedService = trustedServices.get(0);
			} else if (Utils.isCollectionNotEmpty(trustedServices)) {
				LOG.info("More than one selected TSP");
				for (TrustedServiceWrapper trustedService : trustedServices) {
					if (isMatch(trustedService)) {
						selectedTrustedService = trustedService;
					}
				}
			}
		}

		if (selectedTrustedService != null) {
			return Collections.singletonList(selectedTrustedService);
		} else {
			return Collections.emptyList();
		}
	}

	private boolean isMatch(TrustedServiceWrapper trustedService) {
		String organizationName = rootCert.getOrganizationName();
		return Utils.areStringsEqual(organizationName, trustedService.getTspName()) || Utils.areStringsEqual(organizationName, trustedService.getServiceName());
	}

}
