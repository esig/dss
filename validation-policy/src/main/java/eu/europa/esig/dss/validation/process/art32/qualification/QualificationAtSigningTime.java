package eu.europa.esig.dss.validation.process.art32.qualification;

import java.util.Date;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationAtSigningTime extends QualificationBlock {

	public QualificationAtSigningTime(CertificateWrapper signingCertificate, Date signingTime) {
		super(signingCertificate, signingTime);
	}

}
