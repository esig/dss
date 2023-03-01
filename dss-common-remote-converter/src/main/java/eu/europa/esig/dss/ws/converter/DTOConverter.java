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

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

/**
 * Contains utils to convert signature creation DTOs
 */
public class DTOConverter {

	private DTOConverter() {
	}

	/**
	 * Converts {@code ToBeSignedDTO} to {@code ToBeSigned} object
	 *
	 * @param toBeSignedDTO {@link ToBeSignedDTO} to convert
	 * @return {@link ToBeSigned}
	 */
	public static ToBeSigned toToBeSigned(ToBeSignedDTO toBeSignedDTO) {
		if (toBeSignedDTO != null) {
			return new ToBeSigned(toBeSignedDTO.getBytes());
		}
		return null;
	}

	/**
	 * Converts {@code ToBeSigned} to {@code ToBeSignedDTO} object
	 *
	 * @param toBeSigned {@link ToBeSigned} to convert
	 * @return {@link ToBeSignedDTO}
	 */
	public static ToBeSignedDTO toToBeSignedDTO(ToBeSigned toBeSigned) {
		if (toBeSigned != null) {
			return new ToBeSignedDTO(toBeSigned.getBytes());
		}
		return null;
	}

	/**
	 * Converts {@code SignatureValueDTO} to {@code SignatureValue} object
	 *
	 * @param signatureValueDTO {@link SignatureValueDTO} to convert
	 * @return {@link SignatureValue}
	 */
	public static SignatureValue toSignatureValue(SignatureValueDTO signatureValueDTO) {
		if (signatureValueDTO != null) {
			return new SignatureValue(signatureValueDTO.getAlgorithm(), signatureValueDTO.getValue());
		}
		return null;
	}

	/**
	 * Converts {@code SignatureValue} to {@code SignatureValueDTO} object
	 *
	 * @param signatureValue {@link SignatureValue} to convert
	 * @return {@link SignatureValueDTO}
	 */
	public static SignatureValueDTO toSignatureValueDTO(SignatureValue signatureValue) {
		if (signatureValue != null) {
			return new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue());
		}
		return null;
	}

	/**
	 * Converts {@code DigestDTO} to {@code Digest} object
	 *
	 * @param digestDTO {@link DigestDTO} to convert
	 * @return {@link Digest}
	 */
	public static Digest toDigest(DigestDTO digestDTO) {
		if (digestDTO != null) {
			return new Digest(digestDTO.getAlgorithm(), digestDTO.getValue());
		}
		return null;
	}

	/**
	 * Converts {@code Digest} to {@code DigestDTO} object
	 *
	 * @param digest {@link Digest} to convert
	 * @return {@link DigestDTO}
	 */
	public static DigestDTO toDigestDTO(Digest digest) {
		if (digest != null) {
			return new DigestDTO(digest.getAlgorithm(), digest.getValue());
		}
		return null;
	}

}
