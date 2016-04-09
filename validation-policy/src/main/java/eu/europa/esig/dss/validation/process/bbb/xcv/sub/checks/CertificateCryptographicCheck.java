package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class CertificateCryptographicCheck extends CryptographicCheck<XmlSubXCV> {

	private final CertificateWrapper certificate;

	public CertificateCryptographicCheck(XmlSubXCV result, CertificateWrapper certificate, Date currentTime, CryptographicConstraint constraint) {
		super(result, certificate, currentTime, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		if (certificate.isTrusted()) {
			return true;
		} else {
			return super.process();
		}
	}

}
