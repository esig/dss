package eu.europa.esig.dss.EN319102.bbb.xcv.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.AbstractCryptographicCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class CertificateCryptographicCheck extends AbstractCryptographicCheck<XmlXCV> {

	public CertificateCryptographicCheck(XmlXCV result, TokenProxy token, Date currentTime, CryptographicConstraint constraint) {
		super(result, token, currentTime, constraint);
	}

}
