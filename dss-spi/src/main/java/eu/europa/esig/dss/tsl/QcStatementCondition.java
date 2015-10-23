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
package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Condition that check a specific QCStatement
 */
public class QcStatementCondition extends Condition {

	private static final long serialVersionUID = -5504958938057542907L;

	private String qcStatementASN1Id = null;

	/**
	 * The default constructor for QcStatementCondition.
	 *
	 * @param qcStatementId
	 */
	public QcStatementCondition(final String qcStatementASN1Id) {
		this.qcStatementASN1Id = qcStatementASN1Id;
	}

	/**
	 * Checks the condition for the given certificate.
	 *
	 * @param certToken
	 *            certificate to be checked
	 * @return
	 */
	@Override
	public boolean check(final CertificateToken certToken) {
		List<String> extensionIdList = DSSASN1Utils.getQCStatementsIdList(certToken);
		return extensionIdList.contains(qcStatementASN1Id);
	}

	@Override
	public String toString(String indent) {
		if (indent == null) {
			indent = "";
		}
		return indent + "QcStatementCondition{" + "qcStatementId='" + qcStatementASN1Id + '\'' + '}';
	}

	@Override
	public String toString() {
		return toString("");
	}
}
