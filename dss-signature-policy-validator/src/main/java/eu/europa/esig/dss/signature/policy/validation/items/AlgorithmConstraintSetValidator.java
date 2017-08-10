package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.List;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.AlgAndLength;
import eu.europa.esig.dss.x509.CertificateToken;

public class AlgorithmConstraintSetValidator implements ItemValidator {
	
	private List<AlgAndLength> algAndLengthRestrictions;
	private String encryptionAlgOID;
	private int keySize;

	public AlgorithmConstraintSetValidator(List<AlgAndLength> algAndLengthRestrictions, CAdESSignature signature) {
		this.algAndLengthRestrictions = algAndLengthRestrictions;
		extractAlgorithmAngLength(signature);
	}

	private void extractAlgorithmAngLength(CAdESSignature signature) {
		SignerInformation signerInformation = signature.getSignerInformation();
		CertificateToken signingCertificateToken = signature.getSigningCertificateToken();
		
		encryptionAlgOID = signerInformation.getEncryptionAlgOID();
		keySize = DSSPKUtils.getPublicKeySize(signingCertificateToken.getPublicKey());
	}

	@Override
	public boolean validate() {
		for (AlgAndLength algAndLength : algAndLengthRestrictions) {
			if (algAndLength.getAlgID().equals(encryptionAlgOID) && algAndLength.getMinKeyLength() <= keySize) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String getErrorDetail() {
		return null;
	}

}
