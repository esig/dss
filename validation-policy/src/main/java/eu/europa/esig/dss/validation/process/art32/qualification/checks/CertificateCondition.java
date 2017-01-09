package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public interface CertificateCondition {

	boolean check(CertificateWrapper certificate);

}
