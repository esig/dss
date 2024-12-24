/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * This class is used to check whether the given certificate contains qualification identifiers
 *
 */
public final class QCTypeIdentifiers {

	/**
	 * Empty constructor
	 */
	private QCTypeIdentifiers() {
		// empty
	}

	/**
	 * Checks whether the certificate contains a QC for eSignature qualifier (oid "0.4.0.1862.1.6.1")
	 *
	 * @param certificate {@link CertificateWrapper} to check
	 * @return TRUE if the certificate contains "qc-type-esign" qualifier, FALSE otherwise
	 */
	public static boolean isQCTypeEsign(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCTypeEnum.QCT_ESIGN);
	}

	/**
	 * Checks whether the certificate contains a QC for eSeal qualifier (oid "0.4.0.1862.1.6.2")
	 *
	 * @param certificate {@link CertificateWrapper} to check
	 * @return TRUE if the certificate contains "qc-type-eseal" qualifier, FALSE otherwise
	 */
	public static boolean isQCTypeEseal(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCTypeEnum.QCT_ESEAL);
	}

	/**
	 * Checks whether the certificate contains a QC for Web Authentication qualifier (oid "0.4.0.1862.1.6.3")
	 *
	 * @param certificate {@link CertificateWrapper} to check
	 * @return TRUE if the certificate contains "qc-type-web" qualifier, FALSE otherwise
	 */
	public static boolean isQCTypeWeb(CertificateWrapper certificate) {
		return hasQCTypeOID(certificate, QCTypeEnum.QCT_WEB);
	}

	private static boolean hasQCTypeOID(CertificateWrapper certificate, QCType qcType) {
		List<QCType> qcTypes = certificate.getQcTypes();
		if (Utils.isCollectionNotEmpty(qcTypes)) {
			return qcTypes.contains(qcType);
		}
		return false;
	}

}
