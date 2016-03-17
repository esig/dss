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

import eu.europa.esig.dss.validation.reports.SignatureType;

/**
 * This class computes the signature type : AdES, AdESqc or QES (see the_strength_of_the_signature.png)
 */
public class SignatureQualification {

	/**
	 * Certificate
	 */
	private static final int QCP = 1;
	private static final int QCPP = 1;
	private static final int QCC = 1;
	private static final int QCSSCD = 1;

	private static final int Cert_QCP_Only = 0;
	private static final int Cert_QCP_QCC = 1;
	private static final int Cert_QCP_QCC_QCSSCD = 2;
	private static final int Cert_QCPP_Only = 3;
	private static final int Cert_QCPP_QCC = 4;
	private static final int Cert_QCPP_QCC_QCSSCD = 5;
	private static final int Cert_QCC_Only = 6;
	private static final int Cert_QCSSCD_Only = 7;
	private static final int Cert_QCC_QCSSCD = 8;
	private static final int Cert_NO_INFO = 9;

	/**
	 * Trusted list
	 */
	private static final int CAQC = 1;
	private static final int QCWithSSCD = 1;
	private static final int QCCNoSSCD = 1;
	private static final int QCSSCDAsInCert = 1;
	private static final int QCForLegalPerson = 1;
	private static final int QCStatement = 1;

	private static final int TL_CAQC = 0;
	private static final int TL_CAQC_QCWithSSCD = 1;
	private static final int TL_CAQC_QCCNoSSCD = 2;
	private static final int TL_CAQC_QCSSCDAsInCert = 3;
	private static final int TL_CAQC_QCForLegalPerson = 4;
	private static final int TL_CAQC_QCWithSSCD_QCStatement = 5;
	private static final int TL_CAQC_QCCNoSSCD_QCStatement = 6;
	private static final int TL_CAQC_QCSSCDAsInCert_QCStatement = 7;
	private static final int TL_CAQC_QCForLegalPerson_QCStatement = 8;
	private static final int TL_NO_CAQC = 9;

	private static final int[][][][] QCPs = new int[2][2][2][2];
	private static final int[][][][][][] TLs = new int[2][2][2][2][2][2];
	private static final SignatureType[][] SIG = new SignatureType[10][10];

	static {

		QCPs[0][0][0][0] = Cert_NO_INFO;
		QCPs[QCP][0][0][0] = Cert_QCP_Only;
		QCPs[QCP][0][QCC][0] = Cert_QCP_QCC;
		QCPs[QCP][0][QCC][QCSSCD] = Cert_QCP_QCC_QCSSCD;
		QCPs[0][QCPP][0][0] = Cert_QCPP_Only;
		QCPs[0][QCPP][QCC][0] = Cert_QCPP_QCC;
		QCPs[0][QCPP][QCC][QCSSCD] = Cert_QCPP_QCC_QCSSCD;
		QCPs[0][0][QCC][0] = Cert_QCC_Only;
		QCPs[0][0][QCC][QCSSCD] = Cert_QCC_QCSSCD;
		QCPs[0][0][0][QCSSCD] = Cert_QCSSCD_Only;

		TLs[CAQC][0][0][0][0][0] = TL_CAQC;
		TLs[CAQC][QCWithSSCD][0][0][0][0] = TL_CAQC_QCWithSSCD;
		TLs[CAQC][0][QCCNoSSCD][0][0][0] = TL_CAQC_QCCNoSSCD;
		TLs[CAQC][0][0][QCSSCDAsInCert][0][0] = TL_CAQC_QCSSCDAsInCert;
		TLs[CAQC][0][0][0][QCForLegalPerson][0] = TL_CAQC_QCForLegalPerson;
		// TLs[CAQC][0][0][0][0][QCStatement] = TL_CAQC_QCStatement;
		TLs[CAQC][QCWithSSCD][0][0][0][QCStatement] = TL_CAQC_QCWithSSCD_QCStatement;
		TLs[CAQC][0][QCCNoSSCD][0][0][QCStatement] = TL_CAQC_QCCNoSSCD_QCStatement;
		TLs[CAQC][0][0][QCSSCDAsInCert][0][QCStatement] = TL_CAQC_QCSSCDAsInCert_QCStatement;
		TLs[CAQC][0][0][0][QCForLegalPerson][QCStatement] = TL_CAQC_QCForLegalPerson_QCStatement;
		TLs[0][0][0][0][0][0] = TL_NO_CAQC;

		// Fill the table with QES and AdESqc (null -> AdES)
		SIG[TL_CAQC][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC][Cert_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QCWithSSCD][Cert_QCP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCC_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD][Cert_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QCCNoSSCD][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCPP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCPP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCPP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD][Cert_QCC_QCSSCD] = SignatureType.AdESqc;

		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert][Cert_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QCForLegalPerson][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson][Cert_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCC_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCSSCD_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCWithSSCD_QCStatement][Cert_NO_INFO] = SignatureType.QES;

		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCPP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCPP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCPP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCSSCD_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCCNoSSCD_QCStatement][Cert_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCSSCD_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCSSCDAsInCert_QCStatement][Cert_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCSSCD_Only] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QCForLegalPerson_QCStatement][Cert_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_NO_CAQC][Cert_QCP_Only] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][Cert_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][Cert_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_NO_CAQC][Cert_QCPP_Only] = SignatureType.QES;
		SIG[TL_NO_CAQC][Cert_QCPP_QCC] = SignatureType.QES;
		SIG[TL_NO_CAQC][Cert_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_NO_CAQC][Cert_QCC_Only] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][Cert_QCC_QCSSCD] = SignatureType.QES;
	}

	static public SignatureType getSignatureType(CertificateQualification certQualif, TLQualification tlQualif) {
		int qTL = TLs[tlQualif.caqc][tlQualif.qcWithSSCD][tlQualif.qcCNoSSCD][tlQualif.qcSSCDAsInCert][tlQualif.qcForLegalPerson][tlQualif.qcStatement];
		int qCert = QCPs[certQualif.qcp][certQualif.qcpp][certQualif.qcc][certQualif.qcsscd];
		SignatureType signatureType = SIG[qTL][qCert];
		if (signatureType == null) {
			signatureType = SignatureType.AdES;
		}
		return signatureType;
	}
}
