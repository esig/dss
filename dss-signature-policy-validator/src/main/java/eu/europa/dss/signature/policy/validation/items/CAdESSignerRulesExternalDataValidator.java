package eu.europa.dss.signature.policy.validation.items;

import eu.europa.dss.signature.policy.validation.items.ItemValidator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;

public class CAdESSignerRulesExternalDataValidator implements ItemValidator {

	private CAdESSignature cadesSignature;
	private Boolean externalSignedData;
	
	public CAdESSignerRulesExternalDataValidator(CAdESSignature cadesSignature, Boolean externalData) {
		this.cadesSignature = cadesSignature;
		this.externalSignedData = externalData;
	}

	/**
	 * True if signed data is external to CMS structure
     * False if signed data part of CMS structure
     * Not present if either allowed
	 */
	@Override
	public boolean validate() {
		if (externalSignedData != null) {
			if (!(cadesSignature.getCmsSignedData().getSignedContent() != null ^ externalSignedData)) {
				return false;
			}
		}
		return true;
	}

}
