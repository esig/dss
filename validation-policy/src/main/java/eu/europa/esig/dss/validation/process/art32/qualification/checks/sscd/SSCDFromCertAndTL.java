package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServiceFilter;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.filter.TrustedServicesFilterFactory;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class SSCDFromCertAndTL implements SSCDStrategy {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> servicesForESign;
	private final QualifiedStatus qualifiedStatus;
	private final Date date;

	public SSCDFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> servicesForESign, QualifiedStatus qualifiedStatus, Date date) {
		this.signingCertificate = signingCertificate;
		this.servicesForESign = servicesForESign;
		this.qualifiedStatus = qualifiedStatus;
		this.date = date;
	}

	@Override
	public SSCDStatus getSSCDStatus() {

		// 1. filter at date
		TrustedServiceFilter filterByDate = TrustedServicesFilterFactory.createFilterByDate(date);
		List<TrustedServiceWrapper> servicesAtGivenDate = filterByDate.filter(servicesForESign);

		// 2. retrieve certificate qualification from the certificate itself
		SSCDStrategy sscdStrategy = SSCDStrategyFactory.createSSCDFromCert(signingCertificate);
		SSCDStatus sscdStatusFromSigCert = sscdStrategy.getSSCDStatus();

		// 1 TSP and 1 TS // TODO improve
		TrustedServiceWrapper trustedService = getUniqueTrustedService(servicesAtGivenDate);

		// 3. Apply TL overruling(s)
		SSCDStrategy sscdFromCertAndTL = SSCDStrategyFactory.createSSCDFromTL(trustedService, qualifiedStatus, sscdStatusFromSigCert);
		return sscdFromCertAndTL.getSSCDStatus();
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
