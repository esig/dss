package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public class CryptographicRevocationsCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks;
	private final String certificateId;

	public CryptographicRevocationsCheck(T result, List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks, 
			String certificateId) {
		super(result, null);
		this.revocationCryptographicChecks = revocationCryptographicChecks;
		this.certificateId = certificateId;
	}

	@Override
	protected boolean process() {
		// if at least one revocation check successed return true indication
		for (CryptographicCheck<XmlPSV> cryptographicCheck : revocationCryptographicChecks) {
			if (cryptographicCheck.process())
				return true;
		}
		return false;
	}

	@Override
	protected String getAdditionalInfo() {		
		String addInfo = AdditionalInfo.REVOCATION_CRYPTOGRAPHIC_CHECK_FAILURE;
		Object[] params = new Object[] { certificateId };
		return MessageFormat.format(addInfo, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ACCCRM;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ACCCRM_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

}
