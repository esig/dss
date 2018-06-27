package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.trust.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * Allowed services are :
 * <ul>
 * <li>cert type T1 = ASi T1</li>
 * <li>cert type T1 = ASi T2 + QCForXXX T2 (overrule)</li>
 * </ul>
 */
public class ServiceByCertificateTypeFilter extends AbstractTrustedServiceFilter {

	private final CertificateWrapper certificate;

	public ServiceByCertificateTypeFilter(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		Date issuance = certificate.getNotBefore();

		if (EIDASUtils.isPostEIDAS(issuance)) {

			final List<String> additionalServiceInfos = service.getAdditionalServiceInfos();
			boolean asiEsign = AdditionalServiceInformation.isForeSignatures(additionalServiceInfos);
			boolean asiEseals = AdditionalServiceInformation.isForeSeals(additionalServiceInfos);
			boolean asiWsa = AdditionalServiceInformation.isForWebAuth(additionalServiceInfos);

			final List<String> capturedQualifiers = service.getCapturedQualifiers();
			boolean qcForEsign = ServiceQualification.isQcForEsig(capturedQualifiers);
			boolean qcForEseals = ServiceQualification.isQcForEseal(capturedQualifiers);
			boolean qcForWSA = ServiceQualification.isQcForWSA(capturedQualifiers);
			boolean onlyOneQcForXXX = qcForEsign ^ qcForEseals ^ qcForWSA;

			TypeStrategy strategy = TypeStrategyFactory.createTypeFromCert(certificate);
			Type certType = strategy.getType();

			boolean overruleForEsign = asiEsign && qcForEsign && onlyOneQcForXXX;
			boolean overruleForEseals = asiEseals && qcForEseals && onlyOneQcForXXX;
			boolean overruleForWSA = asiWsa && qcForWSA && onlyOneQcForXXX;

			switch (certType) {
			case ESIGN:
				return asiEsign || overruleForEseals || overruleForWSA;
			case ESEAL:
				return asiEseals || overruleForEsign || overruleForWSA;
			case WSA:
				return asiWsa || overruleForEseals || overruleForEsign;
			default:
				return false;
			}

		}

		return true;
	}

}
