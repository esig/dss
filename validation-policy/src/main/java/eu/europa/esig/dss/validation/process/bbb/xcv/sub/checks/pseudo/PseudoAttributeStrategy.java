package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PseudoAttributeStrategy implements PseudoStrategy {

	@Override
	public String getPseudo(CertificateWrapper certificate) {
		return certificate.getPseudo();
	}

}
