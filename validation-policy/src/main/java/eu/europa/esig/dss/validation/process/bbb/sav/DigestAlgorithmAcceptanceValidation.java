package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestCryptographicCheck;

public class DigestAlgorithmAcceptanceValidation extends Chain<XmlSAV> {
	
	protected final DigestAlgorithm digestAlgorithm;
	protected final Date currentTime;
	protected final Context context;
	protected final ValidationPolicy validationPolicy;

	public DigestAlgorithmAcceptanceValidation(Date currentTime, DigestAlgorithm digestAlgorithm, ValidationPolicy validationPolicy, Context context) {
		super(new XmlSAV());
		this.digestAlgorithm = digestAlgorithm;
		this.currentTime = currentTime;
		this.validationPolicy = validationPolicy;
		this.context = context;
	}
	
	@Override
	protected void initChain() {
		firstItem = digestCryptographic();
	}

	protected ChainItem<XmlSAV> digestCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new DigestCryptographicCheck(result, digestAlgorithm, currentTime, constraint);
	}

}
