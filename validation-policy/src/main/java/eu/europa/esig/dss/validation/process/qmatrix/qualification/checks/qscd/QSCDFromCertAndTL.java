package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class QSCDFromCertAndTL extends AbstractQSCDCondition {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;
	private final Condition qualified;
	private final Date date;

	public QSCDFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caqcServices, Condition qualified, Date date) {
		this.signingCertificate = signingCertificate;
		this.caqcServices = caqcServices;
		this.qualified = qualified;
		this.date = date;
	}

	@Override
	public boolean check() {

		// 1. filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> servicesAtGivenDate = filterByDate.filter(caqcServices);

		// 2. retrieve certificate qualification from the certificate itself
		Condition qscdInCert = QSCDConditionFactory.createQSCDFromCert(signingCertificate);

		// 3. Apply TL overruling(s)
		Condition qscdFromCertAndTL = QSCDConditionFactory.createQSCDFromTL(servicesAtGivenDate, qualified, qscdInCert);
		return qscdFromCertAndTL.check();
	}

}
