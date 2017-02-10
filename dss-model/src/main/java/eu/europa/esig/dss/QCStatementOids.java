package eu.europa.esig.dss;

public enum QCStatementOids implements EtsiOid {

	// --- ETSI EN 319 412-5

	/**
	 * esi4-qcStatement-1 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcCompliance }
	 * id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::= { id-etsi-qcs 1 }
	 */
	QC_COMPLIANT("qc-compliant", "0.4.0.1862.1.1"),

	/**
	 * esi4-qcStatement-4 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcSSCD }
	 * id-etsi-qcs-QcSSCD OBJECT IDENTIFIER ::= { id-etsi-qcs 4 }
	 */
	QC_SSCD("qc-sscd", "0.4.0.1862.1.4"),

	/**
	 * esi4-qcStatement-6 QC-STATEMENT ::= { SYNTAX QcType IDENTIFIED
	 * BY id-etsi-qcs-QcType }
	 * Id-etsi-qcs-QcType OBJECT IDENTIFIER ::= { id-etsi-qcs 6 }
	 * QcType::= SEQUENCE {
	 * qcType OBJECT IDENTIFIER {{id-etsi-qct-esign | id-etsi-qct-eseal |
	 * id-etsi-qct-web, ...}}}
	 * -- QC type identifiers
	 * id-etsi-qct-esign OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 1 }
	 * -- Certificate for electronic signatures as defined in Regulation (EU) No 910/2014
	 * id-etsi-qct-eseal OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 2 }
	 * -- Certificate for electronic seals as defined in Regulation (EU) No 910/2014
	 * id-etsi-qct-web OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 3 }
	 * -- Certificate for website authentication as defined in Regulation (EU) No 910/2014
	 */
	QTC_ESIGN("qc-type-esign", "0.4.0.1862.1.6.1"),

	QTC_ESEAL("qc-type-eseal", "0.4.0.1862.1.6.2"),

	QTC_WEB("qc-type-web", "0.4.0.1862.1.6.3");

	private final String description;
	private final String oid;

	QCStatementOids(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
