package eu.europa.esig.dss.validation.process.qmatrix.qualification;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;

public final class QualificationMatrix {

	private QualificationMatrix() {
	}

	private static final int NOT_ADES = 0;
	private static final int ADES = 1;
	private static final int INDETERMINATE_ADES = 2;

	private static final int NOT_QC = 0;
	private static final int QC = 1;

	private static final int ESIG = 0;
	private static final int ESEAL = 1;
	private static final int UNKNOWN = 2;

	private static final int NOT_QSCD = 0;
	private static final int QSCD = 1;

	private static final SignatureQualification[][][][] QUALIFS = new SignatureQualification[3][2][3][2];

	static {

		// AdES

		QUALIFS[ADES][QC][ESIG][QSCD] = SignatureQualification.QESIG;
		QUALIFS[ADES][QC][ESEAL][QSCD] = SignatureQualification.QESEAL;
		QUALIFS[ADES][QC][UNKNOWN][QSCD] = SignatureQualification.QES;

		QUALIFS[ADES][QC][ESIG][NOT_QSCD] = SignatureQualification.ADESIG_QC;
		QUALIFS[ADES][QC][ESEAL][NOT_QSCD] = SignatureQualification.ADESEAL_QC;
		QUALIFS[ADES][QC][UNKNOWN][NOT_QSCD] = SignatureQualification.ADES_QC;

		QUALIFS[ADES][NOT_QC][ESIG][NOT_QSCD] = SignatureQualification.ADESIG;
		QUALIFS[ADES][NOT_QC][ESEAL][NOT_QSCD] = SignatureQualification.ADESEAL;
		QUALIFS[ADES][NOT_QC][UNKNOWN][NOT_QSCD] = SignatureQualification.ADES;

		QUALIFS[ADES][NOT_QC][ESIG][QSCD] = SignatureQualification.ADESIG;
		QUALIFS[ADES][NOT_QC][ESEAL][QSCD] = SignatureQualification.ADESEAL;
		QUALIFS[ADES][NOT_QC][UNKNOWN][QSCD] = SignatureQualification.ADES;

		// Indeterminate AdES

		QUALIFS[INDETERMINATE_ADES][QC][ESIG][QSCD] = SignatureQualification.INDETERMINATE_QESIG;
		QUALIFS[INDETERMINATE_ADES][QC][ESEAL][QSCD] = SignatureQualification.INDETERMINATE_QESEAL;
		QUALIFS[INDETERMINATE_ADES][QC][UNKNOWN][QSCD] = SignatureQualification.INDETERMINATE_QES;

		QUALIFS[INDETERMINATE_ADES][QC][ESIG][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADESIG_QC;
		QUALIFS[INDETERMINATE_ADES][QC][ESEAL][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADESEAL_QC;
		QUALIFS[INDETERMINATE_ADES][QC][UNKNOWN][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADES_QC;

		QUALIFS[INDETERMINATE_ADES][NOT_QC][ESIG][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADESIG;
		QUALIFS[INDETERMINATE_ADES][NOT_QC][ESEAL][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADESEAL;
		QUALIFS[INDETERMINATE_ADES][NOT_QC][UNKNOWN][NOT_QSCD] = SignatureQualification.INDETERMINATE_ADES;

		QUALIFS[INDETERMINATE_ADES][NOT_QC][ESIG][QSCD] = SignatureQualification.INDETERMINATE_ADESIG;
		QUALIFS[INDETERMINATE_ADES][NOT_QC][ESEAL][QSCD] = SignatureQualification.INDETERMINATE_ADESEAL;
		QUALIFS[INDETERMINATE_ADES][NOT_QC][UNKNOWN][QSCD] = SignatureQualification.INDETERMINATE_ADES;

		// Not AdES

		QUALIFS[NOT_ADES][QC][ESIG][QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;
		QUALIFS[NOT_ADES][QC][ESEAL][QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;
		QUALIFS[NOT_ADES][QC][UNKNOWN][QSCD] = SignatureQualification.NOT_ADES_QC_QSCD;

		QUALIFS[NOT_ADES][QC][ESIG][NOT_QSCD] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QC][ESEAL][NOT_QSCD] = SignatureQualification.NOT_ADES_QC;
		QUALIFS[NOT_ADES][QC][UNKNOWN][NOT_QSCD] = SignatureQualification.NOT_ADES_QC;

		QUALIFS[NOT_ADES][NOT_QC][ESIG][NOT_QSCD] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][NOT_QC][ESEAL][NOT_QSCD] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][NOT_QC][UNKNOWN][NOT_QSCD] = SignatureQualification.NOT_ADES;

		QUALIFS[NOT_ADES][NOT_QC][ESIG][QSCD] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][NOT_QC][ESEAL][QSCD] = SignatureQualification.NOT_ADES;
		QUALIFS[NOT_ADES][NOT_QC][UNKNOWN][QSCD] = SignatureQualification.NOT_ADES;

	}

	public static SignatureQualification getSignatureQualification(Indication ades, boolean qc, Type type, boolean qscd) {
		return QUALIFS[getInt(ades)][getInt(qc)][getInt(type)][getInt(qscd)];
	}

	private static int getInt(Type type) {
		switch (type) {
		case ESIGN:
			return ESIG;
		case ESEAL:
		case WSA:
			return ESEAL;
		default:
			return UNKNOWN;
		}
	}

	private static int getInt(boolean bool) {
		return bool ? 1 : 0;
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
}
