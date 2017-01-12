package eu.europa.esig.dss.validation.process.art32.qualification.checks.pseudo;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class CertificateHasPseudoCondition implements CertificateCondition {

	private final CertificateWrapper certificate;

	public CertificateHasPseudoCondition(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public boolean check() {
		JoinedPseudoStrategy multiStrategies = new JoinedPseudoStrategy();
		return Utils.isStringNotBlank(multiStrategies.getPseudo(certificate));
	}

}
