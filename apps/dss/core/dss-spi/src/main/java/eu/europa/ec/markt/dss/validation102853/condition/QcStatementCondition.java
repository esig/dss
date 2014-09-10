/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.condition;

import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * Condition that check a specific QCStatement
 *
 * @version $Revision: 1045 $ - $Date: 2011-06-27 11:07:14 +0200 (Mon, 27 Jun 2011) $
 */

public class QcStatementCondition extends Condition {

	private static final long serialVersionUID = -5504958938057542907L;

	private String qcStatementId = null;

	/**
	 * The default constructor for QcStatementCondition.
	 *
	 * @param qcStatementId
	 */
	public QcStatementCondition(final String qcStatementId) {

		this.qcStatementId = qcStatementId;
	}

	/**
	 * The default constructor for QcStatementCondition.
	 *
	 * @param qcStatementId
	 */
	public QcStatementCondition(final ASN1ObjectIdentifier qcStatementId) {

		this(qcStatementId.getId());
	}

	/**
	 * Checks the condition for the given certificate.
	 *
	 * @param x509Certificate certificate to be checked
	 * @return
	 */
	@Override
	public boolean check(final CertificateToken x509Certificate) {

		final List<String> extensionIdList = x509Certificate.getQCStatementsIdList();
		return extensionIdList.contains(qcStatementId);
	}

	@Override
	public String toString(String indent) {

		if (indent == null) {
			indent = "";
		}
		return indent + "QcStatementCondition{" +
			  "qcStatementId='" + qcStatementId + '\'' +
			  '}';
	}

	@Override
	public String toString() {
		return toString("");
	}
}
