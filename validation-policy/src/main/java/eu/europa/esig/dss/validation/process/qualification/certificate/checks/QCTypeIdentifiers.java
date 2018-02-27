package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.List;

import eu.europa.esig.dss.QCStatementOids;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public final class QCTypeIdentifiers {

	private QCTypeIdentifiers() {
	}

	public static boolean isQCTypeEsign(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCStatementOids.QCT_ESIGN);
	}

	public static boolean isQCTypeEseal(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCStatementOids.QCT_ESEAL);
	}

	public static boolean isQCTypeWeb(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCStatementOids.QCT_WEB);
	}

	private static boolean hasQCTypeOID(CertificateWrapper certificate, QCStatementOids... qcStatements) {
		List<String> qcTypes = certificate.getQCTypes();
		if (Utils.isCollectionNotEmpty(qcTypes)) {
			for (QCStatementOids qcStatement : qcStatements) {
				if (qcTypes.contains(qcStatement.getOid())) {
					return true;
				}
			}
		}
		return false;
	}

}
