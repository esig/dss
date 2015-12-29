package eu.europa.esig.dss.EN319102.bbb.sav.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.AbstractCryptographicCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class SignatureCryptographicCheck extends AbstractCryptographicCheck<XmlSAV> {

	public SignatureCryptographicCheck(XmlSAV result, SignatureWrapper signature, Date currentTime, CryptographicConstraint constraint) {
		super(result, signature, currentTime, constraint);
	}

}
