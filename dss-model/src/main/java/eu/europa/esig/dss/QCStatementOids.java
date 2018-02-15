package eu.europa.esig.dss;

public enum QCStatementOids implements OidDescription {

	// --- ETSI EN 319 412-5

	/**
	 * QCStatement claiming that the certificate is a EU qualified certificate
	 * esi4-qcStatement-1 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcCompliance }
	 * id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::= { id-etsi-qcs 1 }
	 */
	QC_COMPLIANCE("qc-compliance", "0.4.0.1862.1.1"),

	/**
	 * QCStatement regarding limits on the value of transactions
	 * esi4-qcStatement-2 QC-STATEMENT ::= { SYNTAX QcEuLimitValue IDENTIFIED BY id-etsi-qcs-QcLimitValue }
	 * id-etsi-qcs-QcLimitValue OBJECT IDENTIFIER ::= { id-etsi-qcs 2 }
	 */
	QC_LIMIT_VALUE("qc-limit-value", "0.4.0.1862.1.2"),

	/**
	 * QCStatement indicating the duration of the retention period of material information
	 * esi4-qcStatement-3 QC-STATEMENT ::= { SYNTAX QcEuRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }
	 * id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs 3 }
	 */
	QC_RETENTION_PERIOD("qc-retention-period", "0.4.0.1862.1.3"),

	/**
	 * QCStatement claiming that the private key related to the certified public key resides in a QSCD
	 * esi4-qcStatement-4 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcSSCD }
	 * id-etsi-qcs-QcSSCD OBJECT IDENTIFIER ::= { id-etsi-qcs 4 }
	 */
	QC_SSCD("qc-sscd", "0.4.0.1862.1.4"),

	/**
	 * QCStatement regarding location of PKI Disclosure Statements (PDS)
	 * esi4-qcStatement-5 QC-STATEMENT ::= { SYNTAX QcEuPDS IDENTIFIED BY id-etsi-qcs-QcPDS }
	 * id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 }
	 */
	QC_PDS("qc-pds", "0.4.0.1862.1.5"),

	/**
	 * QCStatement claiming that the certificate is a EU qualified certificate of a particular type
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
	QCT_ESIGN("qc-type-esign", "0.4.0.1862.1.6.1"),

	QCT_ESEAL("qc-type-eseal", "0.4.0.1862.1.6.2"),

	QCT_WEB("qc-type-web", "0.4.0.1862.1.6.3");

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
