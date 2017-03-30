package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QualificationFromCertAndTL extends AbstractQualificationCondition {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;
	private final Date date;

	public QualificationFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices, Date date) {
		this.signingCertificate = signingCertificate;
		this.caqcServices = caqcServices;
		this.date = date;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {

		// 1. filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> servicesAtGivenDate = filterByDate.filter(caqcServices);

		// 2. retrieve certificate qualification from the certificate itself
		QualificationStrategy qualificationInCert = QualificationStrategyFactory.createQualificationFromCert(signingCertificate);

		// 3. Apply TL overruling(s)
		QualificationStrategy qualificationFromCertAndTL = QualificationStrategyFactory.createQualificationFromTL(servicesAtGivenDate, qualificationInCert);

		return qualificationFromCertAndTL.getQualifiedStatus();
	}

}
