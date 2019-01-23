package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestCryptographicCheck;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class DigestAlgorithmAcceptanceValidation extends Chain<XmlSAV> {
	
	String digestAlgorithmName;
	Date currentTime;
	Context context;
	ValidationPolicy validationPolicy;

	public DigestAlgorithmAcceptanceValidation(Date currentTime, String digestAlgorithmName, ValidationPolicy validationPolicy, Context context) {
		super(new XmlSAV());
		this.digestAlgorithmName = digestAlgorithmName;
		this.currentTime = currentTime;
		this.validationPolicy = validationPolicy;
		this.context = context;
	}
	
	@Override
	protected void initChain() {
		firstItem = digestCryptographic();
	}

	private ChainItem<XmlSAV> digestCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new DigestCryptographicCheck<XmlSAV>(result, digestAlgorithmName, currentTime, constraint);
	}

}
