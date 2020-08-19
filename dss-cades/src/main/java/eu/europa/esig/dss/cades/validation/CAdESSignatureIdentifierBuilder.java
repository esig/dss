package eu.europa.esig.dss.cades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.validation.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class CAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	public CAdESSignatureIdentifierBuilder(CAdESSignature signature) {
		super(signature);
	}
	
	@Override
	protected void writeParams(ByteArrayOutputStream baos) throws IOException {
		super.writeParams(baos);
		writeString(baos, getSignerInformationValue((CAdESSignature) signature));
	}
	
	private String getSignerInformationValue(CAdESSignature cadesSignature) {
		Integer uniqueInteger = getUniqueIntegerIfNeeded(cadesSignature);
		String masterSignatureId = getMasterSignatureId(cadesSignature);
		
		return masterSignatureId != null ? uniqueInteger.toString() + "-" + masterSignatureId : uniqueInteger.toString();
	}
	
	/**
	 * Returns the related position of {@code this.signerInformation} in the cmsSignedData
	 * among signers with the same SID
	 * 
	 * @param cadesSignature {@link CAdESSignature}
	 * @return integer identifier
	 */
	private int getUniqueIntegerIfNeeded(CAdESSignature cadesSignature) {
		Collection<SignerInformation> signerInformations;
		SignerId signerId = cadesSignature.getSignerId();
		if (cadesSignature.isCounterSignature()) {
			signerInformations = cadesSignature.getSignerInformation().getCounterSignatures().getSigners(signerId);
		} else {
			signerInformations = cadesSignature.getCmsSignedData().getSignerInfos().getSigners(signerId);
		}
		int counter = 0;
		for (SignerInformation currentSignerInformation : signerInformations) {
			if (cadesSignature.getSignerInformation() == currentSignerInformation) {
				break;
			}
			counter++;
		}
		return counter;
	}
	
	/**
	 * Returns Id of the {@code masterSignature} if exists, otherwise returns NULL
	 * 
	 * @param cadesSignature {@link CAdESSignature}
	 * @return {@link String} masterSignature id
	 */
	private String getMasterSignatureId(CAdESSignature cadesSignature) {
		AdvancedSignature masterSignature = cadesSignature.getMasterSignature();
		if (masterSignature != null) {
			return masterSignature.getId();
		}
		return null;
	}

}
