package eu.europa.esig.dss.signature.policy.validation.items;

import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.SignerRules;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class SignPolExtensionValidatorFactory {

	public static ItemValidator createValidator(AdvancedSignature signature, Object currentObj) {
		CollectionItemValidator itemValidator = new CollectionItemValidator();
		if (currentObj instanceof SignerRules) {
			SignerRules signerRules = (SignerRules) currentObj;
			for(SignPolExtn extn: signerRules.getSignPolExtensions()) {
				if (extn.getExtnID().equals(ASN1PBADMandatedPdfSigDicEntries.OID)) {
					PBADMandatedPdfSigDicEntries restriction = ASN1PBADMandatedPdfSigDicEntries.getInstance(extn.getExtnValue());
					itemValidator.add(new PBADPdfEntryValidator(signature, restriction));
				}
			}
		}
		// If there is nothing to validate or the validation is unknown, return an empty ItemValidator
		return itemValidator;
	}

}
