package eu.europa.esig.dss.tsl.dto.condition;

import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.tsl.Condition;

public class QCStatementCondition implements Condition {

	private static final long serialVersionUID = -446434899721093605L;

	private final List<String> qcStatementOids;

	public QCStatementCondition(List<String> qcStatementOids) {
		this.qcStatementOids = qcStatementOids;
	}

	@Override
	public boolean check(CertificateToken certificateToken) {
		List<String> qcStatementsIdInCert = DSSASN1Utils.getQCStatementsIdList(certificateToken);

		for (String expectedOid : qcStatementOids) {
			if (!qcStatementsIdInCert.contains(expectedOid)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(indent).append("QCStatementCondition: ").append(qcStatementOids).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

}
