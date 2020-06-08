package eu.europa.esig.dss.tsl.dto.condition;

import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
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

	@Override
	public boolean check(CertificateToken certificateToken) {

		List<String> qcStatementsIdInCert = DSSASN1Utils.getQCStatementsIdList(certificateToken);

		if (qcStatementsIdInCert.contains(oid)) {

			if (Utils.isStringNotEmpty(type)) {
				List<String> qcTypesIdList = DSSASN1Utils.getQCTypesIdList(certificateToken);
				return qcTypesIdList.contains(type);
			}

			if (Utils.isStringNotEmpty(legislation)) {
				List<String> currentLegs = DSSASN1Utils.getQCLegislations(certificateToken);
				return currentLegs.contains(legislation);
			}

			return true;
		}

		return false;
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
