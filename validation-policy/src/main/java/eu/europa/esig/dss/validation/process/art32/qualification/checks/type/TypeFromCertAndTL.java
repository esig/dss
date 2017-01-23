package eu.europa.esig.dss.validation.process.art32.qualification.checks.type;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TypeFromCertAndTL implements TypeStrategy {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;
	private final Date date;

	public TypeFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices, Date date) {
		this.signingCertificate = signingCertificate;
		this.caqcServices = caqcServices;
		this.date = date;
	}

	@Override
	public Type getType() {

		// 1. filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> servicesAtGivenDate = filterByDate.filter(caqcServices);

		// 2. retrieve certificate type from the certificate itself
		TypeStrategy typeInCert = TypeStrategyFactory.createTypeFromCert(signingCertificate);

		// 1 TSP and 1 TS // TODO improve
		TrustedServiceWrapper trustedService = getUniqueTrustedService(servicesAtGivenDate);

		// 3. Apply TL overruling(s)
		TypeStrategy typeFromCertAndTL = TypeStrategyFactory.createTypeFromTL(trustedService, typeInCert);

		return typeFromCertAndTL.getType();
	}

	private TrustedServiceWrapper getUniqueTrustedService(List<TrustedServiceWrapper> servicesAtGivenDate) {
		int tspsSize = Utils.collectionSize(servicesAtGivenDate);
		if (tspsSize > 1) {
			throw new DSSException("More than one Trusted Service");
		} else if (tspsSize == 1) {
			return servicesAtGivenDate.get(0);
		}
		return null;
	}

}
