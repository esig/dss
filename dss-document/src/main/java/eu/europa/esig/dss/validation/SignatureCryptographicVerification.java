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
package eu.europa.esig.dss.validation;

import java.io.Serializable;

public class SignatureCryptographicVerification implements Serializable {

	private boolean referenceDataFound;

	private boolean referenceDataIntact;

	/**
	 * This can be true but the {@code signatureValid} can be false
	 */
	private boolean signatureIntact;

	private String errorMessage = "";

	public boolean isReferenceDataFound() {

		return referenceDataFound;
	}

	public void setReferenceDataFound(boolean referenceDataFound) {

		this.referenceDataFound = referenceDataFound;
	}

	public boolean isReferenceDataIntact() {

		return referenceDataIntact;
	}

	public void setReferenceDataIntact(boolean referenceDataIntact) {

		this.referenceDataIntact = referenceDataIntact;
	}

	public boolean isSignatureIntact() {

		return signatureIntact;
	}

	public void setSignatureIntact(boolean signatureIntact) {

		this.signatureIntact = signatureIntact;
	}

	/**
	 * This means that the {@code referenceDataFound} and {@code referenceDataIntact} and {@code signatureValid} are true
	 */
	public boolean isSignatureValid() {

		return referenceDataFound && signatureIntact && referenceDataIntact;
	}

	public String getErrorMessage() {

		return errorMessage;
	}

	public void setErrorMessage(final String errorMessage) {

		if (this.errorMessage != null && !this.errorMessage.isEmpty()) {

			this.errorMessage += "<br/>\n" + errorMessage;
		} else {

			this.errorMessage = errorMessage;
		}
	}

	@Override
	public String toString() {

		return "referenceDataFound:" + referenceDataFound + ", referenceDataIntact:" + referenceDataIntact + ", signatureValid;" + signatureIntact + " / " + errorMessage;
	}
}
