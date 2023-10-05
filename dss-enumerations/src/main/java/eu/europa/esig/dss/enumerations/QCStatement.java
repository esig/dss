/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

import java.util.Objects;

/**
 * Defines QCStatements based on ETSI EN 319 412-5
 */
public enum QCStatement implements OidDescription {

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
	 * esi4-qcStatement-6 QC-STATEMENT ::= { SYNTAX QcType IDENTIFIED BY id-etsi-qcs-QcType }
	 * Id-etsi-qcs-QcType OBJECT IDENTIFIER ::= { id-etsi-qcs 6 }
	 * QcType::= SEQUENCE {
	 * qcType OBJECT IDENTIFIER {{id-etsi-qct-esign | id-etsi-qct-eseal | id-etsi-qct-web, ...}}}
	 */
	QC_TYPE("qc-type", "0.4.0.1862.1.6"),

	/**
	 * esi4-qcStatement-7 QC-STATEMENT ::= { SYNTAX QcCClegislation IDENTIFIED BY id-etsi-qcsQcCClegislation }
	 * id-etsi-qcs-QcCClegislation OBJECT IDENTIFIER ::= { id-etsi-qcs 7 }
	 */
	QC_CCLEGISLATION("qc-cclegislation", "0.4.0.1862.1.7");

	/** User-friendly identifier */
	private final String description;

	/** Object identifier */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String} user-friendly identifier
	 * @param oid {@link String} OID
	 */
	QCStatement(String description, String oid) {
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

	/**
	 * Gets a QCStatement for the given label description string
	 *
	 * @param description {@link String}
	 * @return {@link QCStatement}
	 */
	public static QCStatement forLabel(String description) {
		Objects.requireNonNull(description, "Description label cannot be null!");
		for (QCStatement qcStatement : values()) {
			if (description.equals(qcStatement.description)) {
				return qcStatement;
			}
		}
		return null;
	}

	/**
	 * Gets a QCStatement for the given OID string
	 *
	 * @param oid {@link String}
	 * @return {@link QCStatement}
	 */
	public static QCStatement forOID(String oid) {
		Objects.requireNonNull(oid, "OID cannot be null!");
		for (QCStatement qcStatement : values()) {
			if (oid.equals(qcStatement.oid)) {
				return qcStatement;
			}
		}
		return null;
	}

}
