/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
