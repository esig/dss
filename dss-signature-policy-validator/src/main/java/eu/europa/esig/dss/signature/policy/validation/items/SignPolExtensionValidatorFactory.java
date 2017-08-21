package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.List;

import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.SignPolExtensions;
import eu.europa.esig.dss.signature.policy.SignPolExtn;
import eu.europa.esig.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class SignPolExtensionValidatorFactory {

	public static ItemValidator createValidator(AdvancedSignature signature, SignPolExtensions extensionsContainer) {
		CollectionItemValidator itemValidator = new CollectionItemValidator();
		List<SignPolExtn> signPolExtensions = extensionsContainer.getSignPolExtensions();
		if (signPolExtensions != null) {
			for(SignPolExtn extn: signPolExtensions) {
				if (extn.getExtnID().equals(PBADMandatedPdfSigDicEntries.OID)) {
					PBADMandatedPdfSigDicEntries restriction = ASN1PBADMandatedPdfSigDicEntries.getInstance(extn.getExtnValue());
					itemValidator.add(new PBADPdfEntryValidator(signature, restriction));
				} else {
					itemValidator.add(new UnkownSignaturePolicyExtension(extn.getExtnID()));
				}
			}
		}
		return itemValidator;
	}

}
