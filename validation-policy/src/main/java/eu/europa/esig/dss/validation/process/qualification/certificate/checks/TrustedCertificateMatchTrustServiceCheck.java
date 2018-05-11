package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TrustedCertificateMatchTrustServiceCheck extends ChainItem<XmlValidationCertificateQualification> {

	private final CertificateWrapper trustedCert;
	private final TrustedServiceWrapper trustService;
	private MessageTag errorMessage = MessageTag.EMPTY;

	public TrustedCertificateMatchTrustServiceCheck(XmlValidationCertificateQualification result, CertificateWrapper trustedCert,
			TrustedServiceWrapper trustService, LevelConstraint constraint) {
		super(result, constraint);

		this.trustedCert = trustedCert;
		this.trustService = trustService;
	}

	@Override
	protected boolean process() {

		String organizationName = trustedCert.getOrganizationName();
		if (Utils.isStringBlank(organizationName)) {
			errorMessage = MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS1;
			return false;
		}

		if (!isMatch()) {
			errorMessage = MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2;
			return false;
		}

		return true;
	}

	private boolean isMatch() {

		List<String> candidates = Arrays.asList(trustedCert.getOrganizationName(), trustedCert.getCommonName(), trustedCert.getOrganizationalUnit(),
				trustedCert.getCertificateDN());
		List<String> possibleMatchers = Arrays.asList(trustService.getTspName(), trustService.getServiceName());

		for (String candidate : candidates) {
			if (Utils.isStringBlank(candidate)) {
				continue;
			}

			for (String matcher : possibleMatchers) {
				if (Utils.areStringsEqualIgnoreCase(candidate, matcher)) {
					return true;
				}
			}
		}

		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_IS_TRUST_CERT_MATCH_SERVICE;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return errorMessage;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
