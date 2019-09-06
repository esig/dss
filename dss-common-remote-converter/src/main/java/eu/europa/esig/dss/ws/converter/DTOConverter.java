package eu.europa.esig.dss.ws.converter;

import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

public class DTOConverter {
	
	public static ToBeSigned toToBeSigned(ToBeSignedDTO toBeSignedDTO) {
		if (toBeSignedDTO != null) {
			return new ToBeSigned(toBeSignedDTO.getBytes());
		}
		return null;
	}
	
	public static ToBeSignedDTO toToBeSignedDTO(ToBeSigned toBeSigned) {
		if (toBeSigned != null) {
			return new ToBeSignedDTO(toBeSigned.getBytes());
		}
		return null;
	}
	
	public static SignatureValue toSignatureValue(SignatureValueDTO signatureValueDTO) {
		if (signatureValueDTO != null) {
			return new SignatureValue(signatureValueDTO.getAlgorithm(), signatureValueDTO.getValue());
		}
		return null;
	}
	
	public static SignatureValueDTO toSignatureValueDTO(SignatureValue signatureValue) {
		if (signatureValue != null) {
			return new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue());
		}
		return null;
	}

}
