package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCTypeIdentifiers;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PostEIDASCertificateQualified implements CertificateQualification {

	@Override
	public QualifiedStatus getQualifiedStatus(CertificateWrapper certificate) {
		boolean qcCompliant = QCStatementPolicyIdentifiers.isQCCompliant(certificate);
		boolean esign = QCTypeIdentifiers.isQCTypeEsign(certificate);
		boolean eseal = QCTypeIdentifiers.isQCTypeEseal(certificate);
		boolean web = QCTypeIdentifiers.isQCTypeWeb(certificate);

		boolean noneType = !(esign || eseal || web);

		if (qcCompliant && (noneType || esign)) {
			return QualifiedStatus.QC_FOR_ESIGN;
		} else if (qcCompliant && (eseal || web)) {
			return QualifiedStatus.QC_NOT_FOR_ESIGN;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
