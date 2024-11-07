/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;
import java.util.Objects;

/**
 * Sign Document DTO request
 */
@SuppressWarnings("serial")
public abstract class AbstractSignDocumentDTO implements Serializable {

	/** The signature parameters */
	private RemoteSignatureParameters parameters;

	/** The SignatureValue */
	private SignatureValueDTO signatureValue;

	/**
	 * Empty constructor
	 */
	protected AbstractSignDocumentDTO() {
		super();
	}

	/**
	 * Default constructor
	 *
	 * @param parameters {@link RemoteSignatureParameters}
	 * @param signatureValue {@link SignatureValueDTO}
	 */
	protected AbstractSignDocumentDTO(RemoteSignatureParameters parameters, SignatureValueDTO signatureValue) {
		super();
		this.parameters = parameters;
		this.signatureValue = signatureValue;
	}

	/**
	 * Gets signature parameters
	 *
	 * @return {@link RemoteSignatureParameters}
	 */
	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	/**
	 * Sets signature parameters
	 *
	 * @param parameters {@link RemoteSignatureParameters}
	 */
	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

	/**
	 * Gets signature value
	 *
	 * @return {@link SignatureValueDTO}
	 */
	public SignatureValueDTO getSignatureValue() {
		return signatureValue;
	}

	/**
	 * Sets signature value
	 *
	 * @param signatureValue {@link SignatureValueDTO}
	 */
	public void setSignatureValue(SignatureValueDTO signatureValue) {
		this.signatureValue = signatureValue;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((parameters == null) ? 0 : parameters.hashCode());
		result = prime * result + ((signatureValue == null) ? 0 : signatureValue.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractSignDocumentDTO other = (AbstractSignDocumentDTO) obj;
		if (!Objects.equals(parameters, other.parameters)) {
			return false;
		}
		if (!Objects.equals(signatureValue, other.signatureValue)) {
			return false;
		}
		return true;
	}

}
