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
package eu.europa.esig.dss.validation.policy;

public class SignatureQualification {

	private static final int QCP = 1;
	private static final int QCPP = 1;
	private static final int QCC = 1;
	private static final int QCSSCD = 1;

	private static final int CAQC = 1;
	private static final int QCWithSSCD = 1;
	private static final int QCCNoSSCD = 1;
	private static final int QCSSCDAsInCert = 1;
	private static final int QCForLegalPerson = 1;

	private static final int Q1 = 1;
	private static final int Q2 = 2;
	private static final int Q3 = 3;

	private static final int[][][][] QCPs = new int[2][2][2][2];
	private static final int[][][][][] TLs = new int[2][2][2][2][2];
	private static final SignatureType[][] SIG = new SignatureType[3][3];

	static {

		QCPs[QCP][0][0][0] = Q1;
		QCPs[QCP][0][QCC][0] = Q1;
		QCPs[0][0][QCC][0] = Q1;

		QCPs[0][0][QCC][QCSSCD] = Q2;
		QCPs[QCP][0][QCC][QCSSCD] = Q2;
		QCPs[0][QCPP][0][0] = Q2;
		QCPs[0][QCPP][QCC][0] = Q2;
		QCPs[0][QCPP][QCC][QCSSCD] = Q2;

		QCPs[0][0][0][QCSSCD] = Q3;

		TLs[CAQC][0][0][0][0] = Q1;
		TLs[CAQC][0][0][QCSSCDAsInCert][0] = Q1;
		TLs[CAQC][0][0][0][QCForLegalPerson] = Q1;
		TLs[CAQC][QCWithSSCD][0][0][0] = Q2;
		TLs[CAQC][0][QCCNoSSCD][0][0] = Q3;

		SIG[0][0] = SignatureType.AdESqc;
		SIG[0][1] = SignatureType.QES;
		SIG[0][2] = SignatureType.AdESqc;

		SIG[1][0] = SignatureType.QES;
		SIG[1][1] = SignatureType.QES;
		SIG[1][2] = SignatureType.AdESqc;

		// SIG[Q3][Q1] = SignatureType.AdES;
		// SIG[Q3][Q2] = SignatureType.AdES;
		// SIG[Q3][Q3] = SignatureType.AdES;
	}

	static public SignatureType getSignatureType(CertificateQualification certQualif, TLQualification tlQualif) {

		int q1 = QCPs[certQualif.qcp][certQualif.qcpp][certQualif.qcc][certQualif.qcsscd];
		if (q1 == 0) {
			q1 = Q3;
		}
		int q2 = TLs[tlQualif.caqc][tlQualif.qcWithSSCD][tlQualif.qcCNoSSCD][tlQualif.qcSSCDAsInCert][tlQualif.qcForLegalPerson];
		if (q2 == 0) {
			q2 = Q1;
		}
		SignatureType signatureType = SIG[q1 - 1][q2 - 1];
		if (signatureType == null) {

			signatureType = SignatureType.AdES;
		}
		return signatureType;
	}
}
