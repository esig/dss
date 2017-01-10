package eu.europa.esig.dss.validation.process.art32.qualification;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationAtCertificateIssuance extends QualificationBlock {

	public QualificationAtCertificateIssuance(CertificateWrapper signingCertificate) {
		super(signingCertificate, signingCertificate.getNotBefore());
	}

}
