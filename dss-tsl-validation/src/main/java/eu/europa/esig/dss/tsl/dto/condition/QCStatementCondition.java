package eu.europa.esig.dss.tsl.dto.condition;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.QcStatements;
import eu.europa.esig.dss.spi.QcStatementUtils;
import eu.europa.esig.dss.spi.tsl.Condition;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class contains an information extracted for a certificate equivalence condition
 *
 */
public class QCStatementCondition implements Condition {

	private static final long serialVersionUID = -446434899721093605L;

	/** QcStatement OID */
	private final String oid;

	/** QcType OID */
	private final String type;

	/** QcCClegislation code */
	private final String legislation;

	/**
	 * Default constructor
	 *
	 * @param oid {@link String} QcStatement OID, when present
	 * @param type {@link String} QcType OID, when present
	 * @param legislation {@link String} QcCClegislation code, when present
	 */
	public QCStatementCondition(String oid, String type, String legislation) {
		this.oid = oid;
		this.type = type;
		this.legislation = legislation;
	}

	/**
	 * Gets the QcStatement OID
	 *
	 * @return {@link String}
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Gets the QcType OID
	 *
	 * @return {@link String}
	 */
	public String getType() {
		return type;
	}

	/**
	 * Gets the QcCClegislation code
	 *
	 * @return {@link String}
	 */
	public String getLegislation() {
		return legislation;
	}

	@Override
	public boolean check(CertificateToken certificateToken) {
		final QcStatements qcStatements = QcStatementUtils.getQcStatements(certificateToken);
		if (qcStatements != null) {
			if (Utils.isStringNotEmpty(oid) && !QcStatementUtils.isQcStatementPresent(qcStatements, oid)) {
				return false;
			}
			if (Utils.isStringNotEmpty(type) && !QcStatementUtils.isQcTypePresent(qcStatements, type)) {
				return false;
			}
			if (Utils.isStringNotEmpty(legislation) && !QcStatementUtils.isQcLegislationPresent(qcStatements, legislation)) {
				return false;
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
