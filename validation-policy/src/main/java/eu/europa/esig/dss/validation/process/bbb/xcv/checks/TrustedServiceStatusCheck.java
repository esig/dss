package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.text.MessageFormat;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlServiceStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlServiceStatusType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.AdditionalInfo;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class TrustedServiceStatusCheck extends AbstractMultiValuesCheckItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final Date usageTime; // timestamp / revocation production
	private final Context context;

	private String serviceStatusStr;

	public TrustedServiceStatusCheck(XmlXCV result, CertificateWrapper certificate, Date usageTime, Context context, MultiValuesConstraint constraint) {
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

		List<XmlTrustedServiceProviderType> tspList = certificate.getCertificateTSPService();
		for (XmlTrustedServiceProviderType trustedServiceProvider : tspList) {
			XmlServiceStatus serviceStatus = trustedServiceProvider.getServiceStatus();
			if (serviceStatus != null && CollectionUtils.isNotEmpty(serviceStatus.getStatusService())) {
				for (XmlServiceStatusType status : serviceStatus.getStatusService()) {
					serviceStatusStr = StringUtils.trim(status.getStatus());
					if (processValueCheck(serviceStatusStr)) {
						Date statusStartDate = status.getStartDate();
						Date statusEndDate = status.getEndDate();
						// The issuing time of the certificate should be into the validity period of the associated
						// service
						if ((usageTime.compareTo(statusStartDate) >= 0) && ((statusEndDate == null) || usageTime.before(statusEndDate))) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	@Override
	protected String getAdditionalInfo() {
		if (StringUtils.isNotEmpty(serviceStatusStr)) {
			Object[] params = new Object[] { serviceStatusStr };
			return MessageFormat.format(AdditionalInfo.TRUSTED_SERVICE_STATUS, params);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.XCV_TSL_ESP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
			return MessageTag.XCV_TSL_ESP_SIG_ANS;
		case COUNTER_SIGNATURE:
			return MessageTag.XCV_TSL_ESP_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.XCV_TSL_ESP_TSP_ANS;
		case REVOCATION:
			return MessageTag.XCV_TSL_ESP_REV_ANS;
		default:
			return MessageTag.XCV_TSL_ESP_ANS;
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
