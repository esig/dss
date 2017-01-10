package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public interface CertificateQualification {

	QualifiedStatus getQualifiedStatus(CertificateWrapper certificate);

}
