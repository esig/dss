package eu.europa.esig.dss.cades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.validation.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ManifestFile;

public class CAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	public CAdESSignatureIdentifierBuilder(CAdESSignature signature) {
		super(signature);
	}
	
	@Override
	protected void writeSignedProperties(ByteArrayOutputStream baos) throws IOException {
		super.writeSignedProperties(baos);
		writeString(baos, getManifestFilename());
	}
	
	private String getManifestFilename() {
		ManifestFile manifestFile = signature.getManifestFile();
		if (manifestFile != null) {
			return manifestFile.getFilename();
		}
		return null;
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		CAdESSignature cadesMasterSignature = (CAdESSignature) masterSignature;
		SignerInformation masterSignerInformation = cadesMasterSignature.getSignerInformation();
		
		return count(masterSignerInformation.getCounterSignatures().getSigners(), cadesSignature.getSignerInformation());
	}

	@Override
	protected Integer getSignatureFilePosition() {
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		
		return count(cadesSignature.getCmsSignedData().getSignerInfos().getSigners(), cadesSignature.getSignerInformation());
	}
	
	private Integer count(Collection<SignerInformation> signerInformationStore, SignerInformation currentSignerInformation) {
		int counter = 0;
		for (SignerInformation signerInformation : signerInformationStore) {
			if (currentSignerInformation == signerInformation) {
				break;
			}
			counter++;
		}
		
		return counter;
	}

}
