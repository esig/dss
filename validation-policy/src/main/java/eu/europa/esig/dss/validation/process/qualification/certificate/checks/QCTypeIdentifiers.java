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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.utils.Utils;

public final class QCTypeIdentifiers {

	private QCTypeIdentifiers() {
	}

	public static boolean isQCTypeEsign(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCType.QCT_ESIGN);
	}

	public static boolean isQCTypeEseal(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCType.QCT_ESEAL);
	}

	public static boolean isQCTypeWeb(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCType.QCT_WEB);
	}

	private static boolean hasQCTypeOID(CertificateWrapper certificate, QCType qcType) {
		List<QCType> qcTypes = certificate.getQCTypes();
		if (Utils.isCollectionNotEmpty(qcTypes)) {
			return qcTypes.contains(qcType);
		}
		return false;
	}

}
