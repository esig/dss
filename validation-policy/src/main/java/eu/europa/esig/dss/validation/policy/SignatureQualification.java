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
public final class SignatureQualification {

	/**
	 * Certificate
	 */
	private static final int QCP = 1;
	private static final int QCPP = 1;
	private static final int QCC = 1;
	private static final int QCSSCD = 1;

	private static final int CERT_QCP_ONLY = 0;
	private static final int CERT_QCP_QCC = 1;
	private static final int CERT_QCP_QCC_QCSSCD = 2;
	private static final int CERT_QCPP_ONLY = 3;
	private static final int CERT_QCPP_QCC = 4;
	private static final int CERT_QCPP_QCC_QCSSCD = 5;
	private static final int CERT_QCC_ONLY = 6;
	private static final int CERT_QCSSCD_ONLY = 7;
	private static final int CERT_QCC_QCSSCD = 8;
	private static final int CERT_NO_INFO = 9;

	/**
	 * Trusted list
	 */
	private static final int CAQC = 1;
	private static final int QC_WITH_SSCD = 1;
	private static final int QC_NO_SSCD = 1;
	private static final int QC_SSCD_AS_IN_CERT = 1;
	private static final int QC_FOR_LEGAL_PERSON = 1;
	private static final int QC_STATEMENT = 1;

	private static final int TL_CAQC = 0;
	private static final int TL_CAQC_QC_WITH_SSCD = 1;
	private static final int TL_CAQC_QC_NO_SSCD = 2;
	private static final int TL_CAQC_QC_SSCD_AS_IN_CERT = 3;
	private static final int TL_CAQC_QC_FOR_LEGAL_PERSON = 4;
	private static final int TL_CAQC_QC_WITH_SSCD_QC_STATEMENT = 5;
	private static final int TL_CAQC_QC_NO_SSCD_QC_STATEMENT = 6;
	private static final int TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT = 7;
	private static final int TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT = 8;
	private static final int TL_NO_CAQC = 9;

	private static final int[][][][] QCPS = new int[2][2][2][2];
	private static final int[][][][][][] TLS = new int[2][2][2][2][2][2];
	private static final SignatureType[][] SIG = new SignatureType[10][10];

	private SignatureQualification() {
	}

	static {

		QCPS[0][0][0][0] = CERT_NO_INFO;
		QCPS[QCP][0][0][0] = CERT_QCP_ONLY;
		QCPS[QCP][0][QCC][0] = CERT_QCP_QCC;
		QCPS[QCP][0][QCC][QCSSCD] = CERT_QCP_QCC_QCSSCD;
		QCPS[0][QCPP][0][0] = CERT_QCPP_ONLY;
		QCPS[0][QCPP][QCC][0] = CERT_QCPP_QCC;
		QCPS[0][QCPP][QCC][QCSSCD] = CERT_QCPP_QCC_QCSSCD;
		QCPS[0][0][QCC][0] = CERT_QCC_ONLY;
		QCPS[0][0][QCC][QCSSCD] = CERT_QCC_QCSSCD;
		QCPS[0][0][0][QCSSCD] = CERT_QCSSCD_ONLY;

		TLS[CAQC][0][0][0][0][0] = TL_CAQC;
		TLS[CAQC][QC_WITH_SSCD][0][0][0][0] = TL_CAQC_QC_WITH_SSCD;
		TLS[CAQC][0][QC_NO_SSCD][0][0][0] = TL_CAQC_QC_NO_SSCD;
		TLS[CAQC][0][0][QC_SSCD_AS_IN_CERT][0][0] = TL_CAQC_QC_SSCD_AS_IN_CERT;
		TLS[CAQC][0][0][0][QC_FOR_LEGAL_PERSON][0] = TL_CAQC_QC_FOR_LEGAL_PERSON;
		// TLs[CAQC][0][0][0][0][QCStatement] = TL_CAQC_QCStatement;
		TLS[CAQC][QC_WITH_SSCD][0][0][0][QC_STATEMENT] = TL_CAQC_QC_WITH_SSCD_QC_STATEMENT;
		TLS[CAQC][0][QC_NO_SSCD][0][0][QC_STATEMENT] = TL_CAQC_QC_NO_SSCD_QC_STATEMENT;
		TLS[CAQC][0][0][QC_SSCD_AS_IN_CERT][0][QC_STATEMENT] = TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT;
		TLS[CAQC][0][0][0][QC_FOR_LEGAL_PERSON][QC_STATEMENT] = TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT;
		TLS[0][0][0][0][0][0] = TL_NO_CAQC;

		// Fill the table with QES and AdESqc (null -> AdES)
		SIG[TL_CAQC][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC][CERT_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCC_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD][CERT_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCPP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCPP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCPP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD][CERT_QCC_QCSSCD] = SignatureType.AdESqc;

		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT][CERT_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON][CERT_QCC_QCSSCD] = SignatureType.QES;

		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCC_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCSSCD_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_WITH_SSCD_QC_STATEMENT][CERT_NO_INFO] = SignatureType.QES;

		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCPP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCPP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCPP_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCSSCD_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_QCC_QCSSCD] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_NO_SSCD_QC_STATEMENT][CERT_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCSSCD_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_SSCD_AS_IN_CERT_QC_STATEMENT][CERT_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCSSCD_ONLY] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_CAQC_QC_FOR_LEGAL_PERSON_QC_STATEMENT][CERT_NO_INFO] = SignatureType.AdESqc;

		SIG[TL_NO_CAQC][CERT_QCP_ONLY] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][CERT_QCP_QCC] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][CERT_QCP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_NO_CAQC][CERT_QCPP_ONLY] = SignatureType.QES;
		SIG[TL_NO_CAQC][CERT_QCPP_QCC] = SignatureType.QES;
		SIG[TL_NO_CAQC][CERT_QCPP_QCC_QCSSCD] = SignatureType.QES;
		SIG[TL_NO_CAQC][CERT_QCC_ONLY] = SignatureType.AdESqc;
		SIG[TL_NO_CAQC][CERT_QCC_QCSSCD] = SignatureType.QES;
	}

	public static SignatureType getSignatureType(CertificateQualification certQualif, TLQualification tlQualif) {
		int qTL = TLS[tlQualif.caqc][tlQualif.qcWithSSCD][tlQualif.qcCNoSSCD][tlQualif.qcSSCDAsInCert][tlQualif.qcForLegalPerson][tlQualif.qcStatement];
		int qCert = QCPS[certQualif.qcp][certQualif.qcpp][certQualif.qcc][certQualif.qcsscd];
		SignatureType signatureType = SIG[qTL][qCert];
		if (signatureType == null) {
			signatureType = SignatureType.AdES;
		}
		return signatureType;
	}
}
