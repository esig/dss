package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TimestampMessageImprintDataFoundCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TimestampMessageImprintDataIntactCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.LevelConstraint;

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
		ChainItem<XmlSAV> item = firstItem = timestampCryptographic();

		// PVA : best place to validate MessageImprintData here
		// This allows to configure the validation with policy and to get a feedback in the UI
		item = item.setNextItem(messageImprintDataFound());
		item = item.setNextItem(messageImprintDataIntact());
	}

	private ChainItem<XmlSAV> timestampCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(Context.TIMESTAMP);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

	private ChainItem<XmlSAV> messageImprintDataFound() {
		LevelConstraint constraint = validationPolicy.getMessageImprintDataFoundConstraint();
		return new TimestampMessageImprintDataFoundCheck(result, token, constraint);
	}

	private ChainItem<XmlSAV> messageImprintDataIntact() {
		LevelConstraint constraint = validationPolicy.getMessageImprintDataIntactConstraint();
		return new TimestampMessageImprintDataIntactCheck(result, token, constraint);
	}

}
