package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestCryptographicCheck;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class MessageImprintDigestAlgorithmValidation extends DigestAlgorithmAcceptanceValidation {

	public MessageImprintDigestAlgorithmValidation(Date currentTime, TimestampWrapper timestamp, ValidationPolicy validationPolicy) {
		super(currentTime, timestamp.getMessageImprint().getDigestMethod(), validationPolicy, Context.TIMESTAMP);
	}
	
	@Override
	protected ChainItem<XmlSAV> digestCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new DigestCryptographicCheck(result, digestAlgorithm, currentTime, constraint) {
			@Override
			protected MessageTag getMessageTag() { return MessageTag.BBB_SAV_TSP_IMSDAV; }
		};
	}

}
