package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServicesFilterFactory;
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

		// 3. Apply TL overruling(s)
		TypeStrategy typeFromCertAndTL = TypeStrategyFactory.createTypeFromTL(servicesAtGivenDate, typeInCert);

		return typeFromCertAndTL.getType();
	}

}
