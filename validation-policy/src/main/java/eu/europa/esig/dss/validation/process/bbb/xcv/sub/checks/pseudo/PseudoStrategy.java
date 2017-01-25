package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public interface PseudoStrategy {

	String getPseudo(CertificateWrapper certificate);

}
