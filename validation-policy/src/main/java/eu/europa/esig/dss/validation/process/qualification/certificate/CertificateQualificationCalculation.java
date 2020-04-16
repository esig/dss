package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;

public class CertificateQualificationCalculation {

	private final CertificateWrapper endEntityCert;
	private final TrustedServiceWrapper caqcTrustService;

	public CertificateQualificationCalculation(CertificateWrapper endEntityCert, TrustedServiceWrapper caqcTrustService) {
		this.endEntityCert = endEntityCert;
		this.caqcTrustService = caqcTrustService;
	}

	public CertificateQualification getQualification() {
		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(endEntityCert, caqcTrustService);
		QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();

		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(endEntityCert, caqcTrustService, qualifiedStatus);
		Type type = typeStrategy.getType();

		QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(endEntityCert, caqcTrustService, qualifiedStatus);
		QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();

		return CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);
	}

}
