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
		return hasQCStatementOID(certificate, QCStatementOids.QC_COMPLIANCE);
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
