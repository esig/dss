package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.wrappers.RevocationWrapper;
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
		firstItem = revocationCryptographic();
	}

	private ChainItem<XmlSAV> revocationCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(Context.REVOCATION);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

}
