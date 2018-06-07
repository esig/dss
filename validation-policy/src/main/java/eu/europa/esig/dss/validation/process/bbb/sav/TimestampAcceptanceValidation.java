package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class TimestampAcceptanceValidation extends AbstractAcceptanceValidation<TimestampWrapper> {

	public TimestampAcceptanceValidation(DiagnosticData diagnosticData, Date currentTime, TimestampWrapper timestamp, ValidationPolicy validationPolicy) {
		super(diagnosticData, timestamp, currentTime, validationPolicy);
	}

	@Override
	protected void initChain() {
		firstItem = timestampCryptographic();

	}

	private ChainItem<XmlSAV> timestampCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(Context.TIMESTAMP);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

}
