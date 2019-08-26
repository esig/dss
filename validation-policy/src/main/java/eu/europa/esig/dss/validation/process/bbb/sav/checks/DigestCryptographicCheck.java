package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;

public class DigestCryptographicCheck extends AbstractCryptographicCheck<XmlSAV> {
	
	private final DigestAlgorithm digestAlgorithm;
	
	public DigestCryptographicCheck(XmlSAV result, DigestAlgorithm digestAlgorithm, Date currentTime, CryptographicConstraint constraint) {
		super(result, currentTime, constraint);
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	protected boolean process() {
		
		// Check digest algorithm
		if (!digestAlgorithmIsReliable(digestAlgorithm))
			return false;
		
		// Check digest algorithm expiration date
		if (!digestAlgorithmIsValidOnValidationDate(digestAlgorithm))
			return false;
		
		return true;
		
	}

}
