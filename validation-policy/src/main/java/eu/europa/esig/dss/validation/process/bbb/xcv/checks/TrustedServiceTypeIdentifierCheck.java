package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.text.MessageFormat;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class TrustedServiceTypeIdentifierCheck extends AbstractMultiValuesCheckItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final Date usageTime; // timestamp / revocation production date
	private final Context context;

	private String serviceTypeStr;

	public TrustedServiceTypeIdentifierCheck(XmlXCV result, CertificateWrapper certificate, Date usageTime, Context context, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
		this.usageTime = usageTime;
		this.context = context;
	}

	@Override
	protected boolean process() {
		String trustedSource = certificate.getLastChainCertificateSource();
		// do not include Trusted list
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		List<TrustedServiceWrapper> trustedServices = certificate.getTrustedServices();
		for (TrustedServiceWrapper trustedService : trustedServices) {
			serviceTypeStr = Utils.trim(trustedService.getType());
			Date statusStartDate = trustedService.getStartDate();
			if (processValueCheck(serviceTypeStr) && statusStartDate != null) {
				Date statusEndDate = trustedService.getEndDate();
				// The issuing time of the certificate should be into the validity period of the associated
				// service
				if ((usageTime.compareTo(statusStartDate) >= 0) && ((statusEndDate == null) || usageTime.before(statusEndDate))) {
					return true;
				}
			}
		}
		return false;

	}

	@Override
	protected String getAdditionalInfo() {
		if (Utils.isStringNotEmpty(serviceTypeStr)) {
			Object[] params = new Object[] { serviceTypeStr };
			return MessageFormat.format(AdditionalInfo.TRUSTED_SERVICE_TYPE, params);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.XCV_TSL_ETIP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
			return MessageTag.XCV_TSL_ETIP_SIG_ANS;
		case COUNTER_SIGNATURE:
			return MessageTag.XCV_TSL_ETIP_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.XCV_TSL_ETIP_TSP_ANS;
		case REVOCATION:
			return MessageTag.XCV_TSL_ETIP_REV_ANS;
		default:
			return MessageTag.XCV_TSL_ETIP_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
