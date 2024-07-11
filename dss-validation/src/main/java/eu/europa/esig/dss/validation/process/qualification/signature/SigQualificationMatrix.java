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
package eu.europa.esig.dss.validation.process.qualification.signature;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;

/**
 * Builds a signature qualification result based on the given parameters
 *
 */
public final class SigQualificationMatrix {

	/**
	 * Empty constructor
	 */
	private SigQualificationMatrix() {
	}

	/** Not AdES signature */
	private static final int NOT_ADES = 0;

	/** AdES signature */
	private static final int ADES = 1;

	/** Intermediate AdES signature */
	private static final int INDETERMINATE_ADES = 2;

	/** Signature with qualified certificate for eSignature with QSCD */
	private static final int QCERT_FOR_ESIG_QSCD = 0;

	/** Signature with qualified certificate for eSeal with QSCD */
	private static final int QCERT_FOR_ESEAL_QSCD = 1;

	/** Signature with qualified certificate for unknown type with QSCD */
	private static final int QCERT_FOR_UNKNOWN_QSCD = 2;

	/** Signature with qualified certificate for eSignature */
	private static final int QCERT_FOR_ESIG = 3;

	/** Signature with qualified certificate for eSeal */
	private static final int QCERT_FOR_ESEAL = 4;

	/** Signature with qualified certificate for Web Authentication */
	private static final int QCERT_FOR_WSA = 5;

	/** Signature with qualified certificate for unknown type */
	private static final int QCERT_FOR_UNKNOWN = 6;

	/** Signature with certificate for eSignature */
	private static final int CERT_FOR_ESIG = 7;

	/** Signature with certificate for eSeal */
	private static final int CERT_FOR_ESEAL = 8;

	/** Signature with certificate for Web Authentication */
	private static final int CERT_FOR_WSA = 9;

	/** Signature with certificate for unknown type */
	private static final int CERT_FOR_UNKNOWN = 10;

	/** Not applicable */
	private static final int NA = 11;

	/**
	 * Double array containing the relationship between qualification parameters and the final signature qualification
	 */
	private static final SignatureQualification[][] QUALIFS = new SignatureQualification[3][12];

	static {

		// AdES

		QUALIFS[ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.QESIG;
		QUALIFS[ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.QESEAL;
		QUALIFS[ADES][QCERT_FOR_UNKNOWN_QSCD] = SignatureQualification.UNKNOWN_QC_QSCD;

		QUALIFS[ADES][QCERT_FOR_ESIG] = SignatureQualification.ADESIG_QC;
		QUALIFS[ADES][QCERT_FOR_ESEAL] = SignatureQualification.ADESEAL_QC;
		QUALIFS[ADES][QCERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[ADES][QCERT_FOR_UNKNOWN] = SignatureQualification.UNKNOWN_QC;

		QUALIFS[ADES][CERT_FOR_ESIG] = SignatureQualification.ADESIG;
		QUALIFS[ADES][CERT_FOR_ESEAL] = SignatureQualification.ADESEAL;
		QUALIFS[ADES][CERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[ADES][CERT_FOR_UNKNOWN] = SignatureQualification.UNKNOWN;

		QUALIFS[ADES][NA] = SignatureQualification.NA;

		// Indeterminate AdES

		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.INDETERMINATE_QESIG;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.INDETERMINATE_QESEAL;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_UNKNOWN_QSCD] = SignatureQualification.INDETERMINATE_UNKNOWN_QC_QSCD;

		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESIG] = SignatureQualification.INDETERMINATE_ADESIG_QC;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESEAL] = SignatureQualification.INDETERMINATE_ADESEAL_QC;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_UNKNOWN] = SignatureQualification.INDETERMINATE_UNKNOWN_QC;

		QUALIFS[INDETERMINATE_ADES][CERT_FOR_ESIG] = SignatureQualification.INDETERMINATE_ADESIG;
		QUALIFS[INDETERMINATE_ADES][CERT_FOR_ESEAL] = SignatureQualification.INDETERMINATE_ADESEAL;
		QUALIFS[INDETERMINATE_ADES][CERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[INDETERMINATE_ADES][CERT_FOR_UNKNOWN] = SignatureQualification.INDETERMINATE_UNKNOWN;

		QUALIFS[INDETERMINATE_ADES][NA] = SignatureQualification.NA;

		// Not AdES

		QUALIFS[NOT_ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;
		QUALIFS[NOT_ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;
		QUALIFS[NOT_ADES][QCERT_FOR_UNKNOWN_QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;

		QUALIFS[NOT_ADES][QCERT_FOR_ESIG] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QCERT_FOR_ESEAL] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QCERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][QCERT_FOR_UNKNOWN] = SignatureQualification.NOT_ADES_QC;

		QUALIFS[NOT_ADES][CERT_FOR_ESIG] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][CERT_FOR_ESEAL] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][CERT_FOR_WSA] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][CERT_FOR_UNKNOWN] = SignatureQualification.NOT_ADES;

		QUALIFS[NOT_ADES][NA] = SignatureQualification.NOT_ADES;

	}

	/**
	 * Gets signature qualification based on the given parameters
	 *
	 * @param ades {@link Indication} representing the final result of EN 319 102-1 AdES validation process
	 * @param certQualification {@link CertificateQualification} of the certificate used to create the signature
	 * @return {@link SignatureQualification}
	 */
	public static SignatureQualification getSignatureQualification(Indication ades, CertificateQualification certQualification) {
		return QUALIFS[getInt(ades)][getInt(certQualification)];
	}

	private static int getInt(Indication indication) {
		switch (indication) {
		case FAILED:
		case TOTAL_FAILED:
			return 0;
		case PASSED:
		case TOTAL_PASSED:
			return 1;
		case INDETERMINATE:
			return 2;
		default:
			throw new IllegalStateException("Unsupported indication " + indication);
		}
	}

	private static int getInt(CertificateQualification certQualification) {
		switch (certQualification) {
		case QCERT_FOR_ESIG_QSCD:
			return QCERT_FOR_ESIG_QSCD;
		case QCERT_FOR_ESEAL_QSCD:
			return QCERT_FOR_ESEAL_QSCD;
		case QCERT_FOR_UNKNOWN_QSCD:
			return QCERT_FOR_UNKNOWN_QSCD;
		case QCERT_FOR_ESIG:
			return QCERT_FOR_ESIG;
		case QCERT_FOR_ESEAL:
			return QCERT_FOR_ESEAL;
		case QCERT_FOR_WSA:
			return QCERT_FOR_WSA;
		case QCERT_FOR_UNKNOWN:
			return QCERT_FOR_UNKNOWN;
		case CERT_FOR_ESIG:
			return CERT_FOR_ESIG;
		case CERT_FOR_ESEAL:
			return CERT_FOR_ESEAL;
		case CERT_FOR_WSA:
			return CERT_FOR_WSA;
		case CERT_FOR_UNKNOWN:
			return CERT_FOR_UNKNOWN;
		case NA:
			return NA;
		default:
			throw new IllegalStateException("Unsupported certificate qualification " + certQualification);
		}
	}

}
