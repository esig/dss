package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.QcStatements;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.utils.Utils;

public class QCStatementCondition implements Condition {

	private static final long serialVersionUID = -446434899721093605L;

	private final String oid;
	private final String type;
	private final String legislation;

	public QCStatementCondition(String oid, String type, String legislation) {
		this.oid = oid;
		this.type = type;
		this.legislation = legislation;
	}

	public String getOid() {
		return oid;
	}

	public String getType() {
		return type;
	}

	public String getLegislation() {
		return legislation;
	}

	@Override
	public boolean check(CertificateToken certificateToken) {
		final QcStatements qcStatements = QcStatementUtils.getQcStatements(certificateToken);
		if (qcStatements != null && QcStatementUtils.isQcStatementPresent(qcStatements, oid)) {
			if (Utils.isStringNotEmpty(type)) {
				return QcStatementUtils.isQcTypePresent(qcStatements, type);
			}
			if (Utils.isStringNotEmpty(legislation)) {
				return QcStatementUtils.isQcLegislationPresent(qcStatements, legislation);
			}
			return true;
		}
		return false;
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(indent).append("QCStatementCondition: ").append('\n');
		builder.append(indent).append("oid: ").append(oid).append('\n');
		builder.append(indent).append("type: ").append(type).append('\n');
		builder.append(indent).append("legislation: ").append(legislation).append('\n');
		return builder.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}
}
