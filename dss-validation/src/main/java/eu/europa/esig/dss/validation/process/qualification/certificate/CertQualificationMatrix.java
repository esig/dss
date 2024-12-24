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

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;

/**
 * This class is used to determine the certificate qualification based on the given qualification parameters
 *
 */
public final class CertQualificationMatrix {

	/**
	 * Empty constrictor
	 */
	private CertQualificationMatrix() {
	}

	/** Not qualified certificate */
	private static final int NOT_QC = 0;

	/** Qualified certificate */
	private static final int QC = 1;

	/** Certificate for eSig */
	private static final int ESIG = 0;

	/** Certificate for eSeal */
	private static final int ESEAL = 1;

	/** Certificate for Web Authentication */
	private static final int WSA = 2;

	/** Certificate type is unknown */
	private static final int UNKNOWN = 3;

	/** Certificate is not for QSCD */
	private static final int NOT_QSCD = 0;

	/** Certificate is for QSCD */
	private static final int QSCD = 1;

	/** Cached cube-array containing qualification results for different sets of parameters */
	private static final CertificateQualification[][][] QUALIFS = new CertificateQualification[2][4][2];

	static {

		QUALIFS[QC][ESIG][QSCD] = CertificateQualification.QCERT_FOR_ESIG_QSCD;
		QUALIFS[QC][ESEAL][QSCD] = CertificateQualification.QCERT_FOR_ESEAL_QSCD;
		QUALIFS[QC][WSA][QSCD] = CertificateQualification.QCERT_FOR_WSA;
		QUALIFS[QC][UNKNOWN][QSCD] = CertificateQualification.QCERT_FOR_UNKNOWN_QSCD;

		QUALIFS[QC][ESIG][NOT_QSCD] = CertificateQualification.QCERT_FOR_ESIG;
		QUALIFS[QC][ESEAL][NOT_QSCD] = CertificateQualification.QCERT_FOR_ESEAL;
		QUALIFS[QC][WSA][NOT_QSCD] = CertificateQualification.QCERT_FOR_WSA;
		QUALIFS[QC][UNKNOWN][NOT_QSCD] = CertificateQualification.QCERT_FOR_UNKNOWN;

		QUALIFS[NOT_QC][ESIG][NOT_QSCD] = CertificateQualification.CERT_FOR_ESIG;
		QUALIFS[NOT_QC][ESEAL][NOT_QSCD] = CertificateQualification.CERT_FOR_ESEAL;
		QUALIFS[NOT_QC][WSA][NOT_QSCD] = CertificateQualification.CERT_FOR_WSA;
		QUALIFS[NOT_QC][UNKNOWN][NOT_QSCD] = CertificateQualification.CERT_FOR_UNKNOWN;

		QUALIFS[NOT_QC][ESIG][QSCD] = CertificateQualification.CERT_FOR_ESIG;
		QUALIFS[NOT_QC][ESEAL][QSCD] = CertificateQualification.CERT_FOR_ESEAL;
		QUALIFS[NOT_QC][WSA][QSCD] = CertificateQualification.CERT_FOR_WSA;
		QUALIFS[NOT_QC][UNKNOWN][QSCD] = CertificateQualification.CERT_FOR_UNKNOWN;

	}

	/**
	 * Returns the certificate's qualification status based on the given parameters
	 *
	 * @param qc {@link CertificateQualifiedStatus}
	 * @param type {@link CertificateType}
	 * @param qscd {@link QSCDStatus}
	 * @return {@link CertificateQualification}
	 */
	public static CertificateQualification getCertQualification(CertificateQualifiedStatus qc, CertificateType type, QSCDStatus qscd) {
		return QUALIFS[getInt(CertificateQualifiedStatus.isQC(qc))][getInt(type)][getInt(QSCDStatus.isQSCD(qscd))];
	}

	private static int getInt(CertificateType type) {
		switch (type) {
		case ESIGN:
			return ESIG;
		case ESEAL:
			return ESEAL;
		case WSA:
			return WSA;
		default:
			return UNKNOWN;
		}
	}

	private static int getInt(boolean bool) {
		return bool ? 1 : 0;
	}

}
