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
package eu.europa.esig.dss.model.signature;

import java.io.Serializable;
import java.util.List;

/**
 * Contains a result if a signature cryptographic validation
 */
public class SignatureCryptographicVerification implements Serializable {

	private static final long serialVersionUID = -7343772251223888821L;

	/** Builds the error message if applicable. Empty value if validation succeeds. */
	private final StringBuilder errorMessageBuilder = new StringBuilder();

	/** Defines if (all) references data found */
	private boolean referenceDataFound;

	/** Defines if (all) references data intact */
	private boolean referenceDataIntact;

	/**
	 * Defines if the SignatureValue is valid
	 *
	 * NOTE: This can be true but the {@code signatureValid} can be false
	 */
	private boolean signatureIntact;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SignatureCryptographicVerification() {
		// empty
	}

	/**
	 * Gets if (all) references data found
	 *
	 * @return if (all) references data found
	 */
	public boolean isReferenceDataFound() {
		return referenceDataFound;
	}

	/**
	 * Sets if (all) references data found
	 *
	 * @param referenceDataFound if (all) references data found
	 */
	public void setReferenceDataFound(boolean referenceDataFound) {
		this.referenceDataFound = referenceDataFound;
	}

	/**
	 * Gets if (all) references data intact
	 *
	 * @return if (all) references data intact
	 */
	public boolean isReferenceDataIntact() {
		return referenceDataIntact;
	}

	/**
	 * Sets if (all) references data intact
	 *
	 * @param referenceDataIntact if (all) references data intact
	 */
	public void setReferenceDataIntact(boolean referenceDataIntact) {
		this.referenceDataIntact = referenceDataIntact;
	}

	/**
	 * Gets if the SignatureValue is valid
	 *
	 * @return if the SignatureValue is valid
	 */
	public boolean isSignatureIntact() {
		return signatureIntact;
	}

	/**
	 * Sets if the SignatureValue is valid
	 *
	 * @param signatureIntact if the SignatureValue is valid
	 */
	public void setSignatureIntact(boolean signatureIntact) {
		this.signatureIntact = signatureIntact;
	}

	/**
	 * Returns if the signature is valid.
	 * This means that the {@code referenceDataFound} and
	 *                     {@code referenceDataIntact} and
	 *                     {@code signatureValid} are true
	 *
	 * @return TRUE if the signature is valid, FALSE otherwise
	 */
	public boolean isSignatureValid() {
		return referenceDataFound && signatureIntact && referenceDataIntact;
	}

	/**
	 * Returns a list of error messages obtained during signature cryptographic verification
	 * 
	 * @return {@link String} error message, empty string "" is signature is valid
	 */
	public String getErrorMessage() {
		return errorMessageBuilder.toString();
	}

	/**
	 * Sets the error message (adds the message to error list)
	 *
	 * @param errorMessage {@link String} to add
	 */
	public void setErrorMessage(final String errorMessage) {
		if (errorMessageBuilder.length() != 0) {
			errorMessageBuilder.append("<br/>\n");
		}
		errorMessageBuilder.append(errorMessage);
	}

	/**
	 * Sets all error messages (adds the messages to error list)
	 *
	 * @param errorMessages a list of {@link String} messages
	 */
	public void setErrorMessages(List<String> errorMessages) {
		if (errorMessages != null && !errorMessages.isEmpty()) {
			for (String errorMessage : errorMessages) {
				setErrorMessage(errorMessage);
			}
		}
	}

	@Override
	public String toString() {
		return "referenceDataFound:" + referenceDataFound + ", referenceDataIntact:" + referenceDataIntact + ", signatureValid;" + signatureIntact + " / " + errorMessageBuilder.toString();
	}

}
