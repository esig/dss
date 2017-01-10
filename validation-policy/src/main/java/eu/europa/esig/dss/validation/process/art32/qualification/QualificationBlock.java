package eu.europa.esig.dss.validation.process.art32.qualification;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationBlock {

	private final CertificateWrapper signingCertificate;
	private final Date date;

	public QualificationBlock(CertificateWrapper signingCertificate, Date date) {
		this.signingCertificate = signingCertificate;
		this.date = date;
	}

	public void execute() {
		List<XmlTrustedServiceProvider> originalTSPs = signingCertificate.getTrustedServiceProviders();

		// 1. filter by service for esign
		TrustedServiceFilter filter = TrustedServicesFilterFactory.createFilterForEsign(date);
		List<XmlTrustedServiceProvider> servicesForESign = filter.filter(originalTSPs);

		// 2. filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<XmlTrustedServiceProvider> servicesAtGivenDate = filterByDate.filter(servicesForESign);

		// 3. filter by country code
		TrustedServiceFilter filterByCountry = TrustedServicesFilterFactory.createFilterByCountry(signingCertificate.getCountryName());
		List<XmlTrustedServiceProvider> servicesAtGivenDateInSameCountry = filterByCountry.filter(servicesAtGivenDate);

		// 4. retrieve certificate qualification from the certificate itself
		QualificationStrategy qualificationStrategy = QualificationStrategyFactory.createQualificationStrategy(signingCertificate);
		QualifiedStatus qualifiedStatusFromSigCert = qualificationStrategy.getQualifiedStatus();

		// 1 TSP and 1 TS
		XmlTrustedService trustedService = getUniqueTrustedService(servicesAtGivenDateInSameCountry);

		// 5. check consistency

		// 6. Apply TL overruling(s)

	}

	private XmlTrustedService getUniqueTrustedService(List<XmlTrustedServiceProvider> servicesAtGivenDate) {
		int tspsSize = Utils.collectionSize(servicesAtGivenDate);
		if (tspsSize > 1) {
			throw new DSSException("More than one Trusted Service Provider");
		} else if (tspsSize == 1) {
			XmlTrustedServiceProvider tsp = servicesAtGivenDate.get(0);
			List<XmlTrustedService> trustedServices = tsp.getTrustedServices();
			int nbTrustedServices = Utils.collectionSize(trustedServices);
			if (nbTrustedServices > 1) {
				throw new DSSException("More than one Trusted Service");
			} else if (nbTrustedServices == 1) {
				return trustedServices.get(0);
			}
		}
		return null;
	}

}
