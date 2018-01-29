package eu.europa.esig.dss.validation.process.qmatrix.qualification;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;

public final class SigQualificationMatrix {

	private SigQualificationMatrix() {
	}

	private static final int NOT_ADES = 0;
	private static final int ADES = 1;
	private static final int INDETERMINATE_ADES = 2;

	private static final int QCERT_FOR_ESIG_QSCD = 0;
	private static final int QCERT_FOR_ESEAL_QSCD = 1;
	private static final int QCERT_FOR_ESIG = 2;
	private static final int QCERT_FOR_ESEAL = 3;
	private static final int QCERT_FOR_WSA = 4;
	private static final int CERT_FOR_ESIG = 5;
	private static final int CERT_FOR_ESEAL = 6;
	private static final int CERT_FOR_WSA = 7;
	private static final int NA = 8;

	private static final SignatureQualification[][] QUALIFS = new SignatureQualification[3][9];

	static {

		// AdES

		QUALIFS[ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.QESIG;
		QUALIFS[ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.QESEAL;

		QUALIFS[ADES][QCERT_FOR_ESIG] = SignatureQualification.ADESIG_QC;
		QUALIFS[ADES][QCERT_FOR_ESEAL] = SignatureQualification.ADESEAL_QC;
		QUALIFS[ADES][QCERT_FOR_WSA] = SignatureQualification.ADES_QC;

		QUALIFS[ADES][CERT_FOR_ESIG] = SignatureQualification.ADESIG;
		QUALIFS[ADES][CERT_FOR_ESEAL] = SignatureQualification.ADESEAL;
		QUALIFS[ADES][CERT_FOR_WSA] = SignatureQualification.ADES;
		QUALIFS[ADES][NA] = SignatureQualification.ADES;

		// Indeterminate AdES

		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.INDETERMINATE_QESIG;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.INDETERMINATE_QESEAL;

		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESIG] = SignatureQualification.INDETERMINATE_ADESIG_QC;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_ESEAL] = SignatureQualification.INDETERMINATE_ADESEAL_QC;
		QUALIFS[INDETERMINATE_ADES][QCERT_FOR_WSA] = SignatureQualification.INDETERMINATE_ADES_QC;

		QUALIFS[INDETERMINATE_ADES][CERT_FOR_ESIG] = SignatureQualification.INDETERMINATE_ADESIG;
		QUALIFS[INDETERMINATE_ADES][CERT_FOR_ESEAL] = SignatureQualification.INDETERMINATE_ADESEAL;
		QUALIFS[INDETERMINATE_ADES][CERT_FOR_WSA] = SignatureQualification.INDETERMINATE_ADES;
		QUALIFS[INDETERMINATE_ADES][NA] = SignatureQualification.INDETERMINATE_ADES;

		// Not AdES

		QUALIFS[NOT_ADES][QCERT_FOR_ESIG_QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;
		QUALIFS[NOT_ADES][QCERT_FOR_ESEAL_QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;

		QUALIFS[NOT_ADES][QCERT_FOR_ESIG] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QCERT_FOR_ESEAL] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QCERT_FOR_WSA] = SignatureQualification.NOT_ADES_QC;

		QUALIFS[NOT_ADES][CERT_FOR_ESIG] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][CERT_FOR_ESEAL] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][CERT_FOR_WSA] = SignatureQualification.NOT_ADES;

		QUALIFS[NOT_ADES][NA] = SignatureQualification.NOT_ADES;
	}

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
			throw new DSSException("Unsupported indication " + indication);
		}
	}

	private static int getInt(CertificateQualification certQualification) {
		switch (certQualification) {
		case QCERT_FOR_ESIG_QSCD:
			return QCERT_FOR_ESIG_QSCD;
		case QCERT_FOR_ESEAL_QSCD:
			return QCERT_FOR_ESEAL_QSCD;
		case QCERT_FOR_ESIG:
			return QCERT_FOR_ESIG;
		case QCERT_FOR_ESEAL:
			return QCERT_FOR_ESEAL;
		case QCERT_FOR_WSA:
			return QCERT_FOR_WSA;
		case CERT_FOR_ESIG:
			return CERT_FOR_ESIG;
		case CERT_FOR_ESEAL:
			return CERT_FOR_ESEAL;
		case CERT_FOR_WSA:
			return CERT_FOR_WSA;
		case NA:
			return NA;
		default:
			throw new DSSException("Unsupported certificate qualification " + certQualification);
		}
	}

}
