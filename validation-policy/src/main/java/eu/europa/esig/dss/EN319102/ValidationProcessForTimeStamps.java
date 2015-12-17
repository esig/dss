package eu.europa.esig.dss.EN319102;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps {

	private ValidationProcessForBasicSignatures processBasicSignatures;

	/**
	 * 5.4.4 1) Token signature validation: the building block shall perform the validation process for Basic Signatures as per
	 * clause 5.3 with the time-stamp token. In all the steps of this process, the building block shall take into account
	 * that the signature to validate is a time-stamp token (e.g. to select TSA trust-anchors). If this step returns
	 * PASSED, the building block shall go to the next step. Otherwise, the building block shall return the indication
	 * and information returned by the validation process.
	 */
	void executeValidationProcessForBasicSignaturesOnTimestamp() {
		processBasicSignatures.executeValidationProcessForBasicSignatures();
	}

	/**
	 * Data extraction: in addition to the data items returned in step 1, the building block:
	 * - shall return the generation time and the message imprint present in the TSTInfo field of the time-stamp
	 * token; and
	 * - may return other data items present in the TSTInfo field of the time-stamp token.
	 * These items may be used by the building block in the process of validating the AdES signature.
	 */
	void dataExtraction() {

	}

}
