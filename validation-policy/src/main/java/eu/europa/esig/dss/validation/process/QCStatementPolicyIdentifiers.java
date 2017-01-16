package eu.europa.esig.dss.validation.process;

import java.util.List;

import eu.europa.esig.dss.QCStatementOids;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

/**
 * Qualified Certificate Statement constants
 */
public final class QCStatementPolicyIdentifiers {

	private QCStatementPolicyIdentifiers() {
	}

	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasQCStatementOID(certificate, QCStatementOids.QC_SSCD);
	}

	public static boolean isQCCompliant(CertificateWrapper certificate) {
		return hasQCStatementOID(certificate, QCStatementOids.QC_COMPLIANT);
	}

	private static boolean hasQCStatementOID(CertificateWrapper certificate, QCStatementOids... qcStatements) {
		List<String> qcStatementIds = certificate.getQCStatementIds();
		if (Utils.isCollectionNotEmpty(qcStatementIds)) {
			for (QCStatementOids qcStatement : qcStatements) {
				if (qcStatementIds.contains(qcStatement.getOid())) {
					return true;
				}
			}
		}
		return false;
	}

}
