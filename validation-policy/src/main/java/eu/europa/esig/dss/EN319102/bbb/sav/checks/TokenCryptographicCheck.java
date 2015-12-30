package eu.europa.esig.dss.EN319102.bbb.sav.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.AbstractCryptographicCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class TokenCryptographicCheck extends AbstractCryptographicCheck<XmlSAV> {

	public TokenCryptographicCheck(XmlSAV result, TokenProxy token, Date currentTime, CryptographicConstraint constraint) {
		super(result, token, currentTime, constraint);
	}

}
