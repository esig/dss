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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import java.security.PublicKey;

/**
 * Verifies integrity of a XAdES signature
 */
public class XAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The relevant Santuario signature instance */
	private final XMLSignature santuarioSignature;

	/**
	 * Default constructor
	 *
	 * @param santuarioSignature {@link XMLSignature}
	 */
	public XAdESSignatureIntegrityValidator(XMLSignature santuarioSignature) {
		this.santuarioSignature = santuarioSignature;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			return santuarioSignature.checkSignatureValue(publicKey);
		} catch (XMLSignatureException e) {
			throw new DSSException(String.format("Unable to verify the signature : %s", e.getMessage()), e);
		}
	}

}
