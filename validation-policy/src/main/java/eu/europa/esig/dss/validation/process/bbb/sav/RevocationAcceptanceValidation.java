package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class RevocationAcceptanceValidation extends AbstractAcceptanceValidation<RevocationWrapper> {

	public RevocationAcceptanceValidation(DiagnosticData diagnosticData, Date currentTime, RevocationWrapper timestamp, ValidationPolicy validationPolicy) {
		super(diagnosticData, timestamp, currentTime, validationPolicy);
	}

	@Override
	protected void initChain() {
		firstItem = addChecksForRevocationCryptographic();
	}

	/**
	 * Method created in order to support multiple constraints.
	 * @return At least one chainitem
	 */
	private ChainItem<XmlSAV> addChecksForRevocationCryptographic() {
		int index = 0;
		ChainItem<XmlSAV> firstItem = null;
		ChainItem<XmlSAV> newItem = null;
		EtsiValidationPolicy epolicy = (EtsiValidationPolicy) validationPolicy;
		CryptographicConstraint constraint;
		do {
			constraint = epolicy.getSignatureCryptographicConstraint(Context.REVOCATION, index);
			if (index == 0 || constraint != null) {
				if (newItem == null) {
					newItem = new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
					firstItem = newItem;
				} else {
					newItem = newItem.setNextItem(new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint));
				}
				index++;
			}
		} while (constraint != null);
		return firstItem;
	}

}
