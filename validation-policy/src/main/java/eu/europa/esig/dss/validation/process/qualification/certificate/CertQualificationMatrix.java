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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.validation.CertificateQualification;

public final class CertQualificationMatrix {

	private CertQualificationMatrix() {
	}

	private static final int NOT_QC = 0;
	private static final int QC = 1;

	private static final int ESIG = 0;
	private static final int ESEAL = 1;
	private static final int WSA = 2;
	private static final int UNKNOWN = 3;

	private static final int NOT_QSCD = 0;
	private static final int QSCD = 1;

	private static final CertificateQualification[][][] QUALIFS = new CertificateQualification[2][4][2];

	static {

		QUALIFS[QC][ESIG][QSCD] = CertificateQualification.QCERT_FOR_ESIG_QSCD;
		QUALIFS[QC][ESEAL][QSCD] = CertificateQualification.QCERT_FOR_ESEAL_QSCD;
		QUALIFS[QC][WSA][QSCD] = CertificateQualification.QCERT_FOR_WSA;
		QUALIFS[QC][UNKNOWN][QSCD] = CertificateQualification.NA;

		QUALIFS[QC][ESIG][NOT_QSCD] = CertificateQualification.QCERT_FOR_ESIG;
		QUALIFS[QC][ESEAL][NOT_QSCD] = CertificateQualification.QCERT_FOR_ESEAL;
		QUALIFS[QC][WSA][NOT_QSCD] = CertificateQualification.QCERT_FOR_WSA;
		QUALIFS[QC][UNKNOWN][NOT_QSCD] = CertificateQualification.NA;

		QUALIFS[NOT_QC][ESIG][NOT_QSCD] = CertificateQualification.CERT_FOR_ESIG;
		QUALIFS[NOT_QC][ESEAL][NOT_QSCD] = CertificateQualification.CERT_FOR_ESEAL;
		QUALIFS[NOT_QC][WSA][NOT_QSCD] = CertificateQualification.CERT_FOR_WSA;
		QUALIFS[NOT_QC][UNKNOWN][NOT_QSCD] = CertificateQualification.NA;

		QUALIFS[NOT_QC][ESIG][QSCD] = CertificateQualification.NA;
		QUALIFS[NOT_QC][ESEAL][QSCD] = CertificateQualification.NA;
		QUALIFS[NOT_QC][WSA][QSCD] = CertificateQualification.NA;
		QUALIFS[NOT_QC][UNKNOWN][QSCD] = CertificateQualification.NA;

	}

	public static CertificateQualification getCertQualification(QualifiedStatus qc, Type type, QSCDStatus qscd) {
		return QUALIFS[getInt(QualifiedStatus.isQC(qc))][getInt(type)][getInt(QSCDStatus.isQSCD(qscd))];
	}

	private static int getInt(Type type) {
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
