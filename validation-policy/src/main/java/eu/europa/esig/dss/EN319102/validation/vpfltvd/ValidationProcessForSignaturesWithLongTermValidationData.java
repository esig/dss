package eu.europa.esig.dss.EN319102.validation.vpfltvd;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfltvd.checks.AcceptableBasicSignatureValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData extends Chain<XmlValidationProcessLongTermData> {

	private final XmlConstraintsConclusion basicSignatureValidation;
	private final XmlConstraintsConclusion timestampValidation;

	public ValidationProcessForSignaturesWithLongTermValidationData(XmlConstraintsConclusion basicSignatureValidation,
			XmlConstraintsConclusion timestampValidation) {
		super(new XmlValidationProcessLongTermData());

		this.basicSignatureValidation = basicSignatureValidation;
		this.timestampValidation = timestampValidation;
	}

	@Override
	protected void initChain() {

		/*
		 * 5.5.4 2) Signature validation: the process shall perform the validation process for Basic Signatures as per
		 * clause 5.3 with all the inputs, including the processing of any signed attributes as specified. If the
		 * Signature contains long-term validation data, this data shall be passed to the validation process for Basic
		 * Signatures.
		 * 
		 * If this validation returns PASSED, INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
		 * INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/OUT_OF_BOUNDS_NO_POE, the SVA
		 * shall go to the next step. Otherwise, the process shall return the status and information returned by the
		 * validation process for Basic Signatures.
		 */
		ChainItem<XmlValidationProcessLongTermData> item = firstItem = isAcceptableBasicSignatureValidation();

	}

	private ChainItem<XmlValidationProcessLongTermData> isAcceptableBasicSignatureValidation() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		return new AcceptableBasicSignatureValidationCheck(result, basicSignatureValidation, constraint);
	}

}
