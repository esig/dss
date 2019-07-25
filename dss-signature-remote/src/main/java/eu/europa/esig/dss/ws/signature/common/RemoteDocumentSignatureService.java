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
package eu.europa.esig.dss.ws.signature.common;

import java.io.Serializable;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

/**
 * This interface {@code RemoteDocumentSignatureService} provides operations for the signature creation and for its
 * extension.
 *
 */
public interface RemoteDocumentSignatureService extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the {@code toSignDocument} and {@code parameters}
	 * .
	 * When {@code toSignDocument} contains an already existing signature the returned bytes are related to a new
	 * parallel signature.
	 *
	 * - Enveloped signature (XML): a new signature is added and the signed data corresponds to that pointed by the
	 * first signature;
	 *
	 * - Enveloping signature:
	 *
	 * - - XML: The parallel signature is not possible
	 *
	 * - - CMS: A new parallel signature is added
	 *
	 * - Detached signature:
	 *
	 * - - XML: The parallel signature is added
	 *
	 * - - CMS: A new parallel signature is added
	 *
	 *
	 * @param toSignDocument
	 *            document to sign or the already existing signature
	 * @param parameters
	 *            set of the driving signing parameters
	 * @return the data to be signed
	 * @throws DSSException
	 *             if an error occurred
	 */
	ToBeSignedDTO getDataToSign(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters) throws DSSException;

	/**
	 * Signs the toSignDocument with the provided signatureValue.
	 *
	 * @param toSignDocument
	 *            document to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param signatureValue
	 *            the signature value to incorporate
	 * @return the signed document ({@code toSignDocument} with the incorporated signature or the detached signature)
	 * @throws DSSException
	 *             if an error occurred
	 */
	RemoteDocument signDocument(final RemoteDocument toSignDocument, final RemoteSignatureParameters parameters, SignatureValueDTO signatureValue) throws DSSException;

	/**
	 * Extends the level of the signatures in the {@code toExtendDocument}
	 *
	 * @param toExtendDocument
	 *            document to extend
	 * @param parameters
	 *            set of the driving signing parameters
	 * @return the extended signature
	 * @throws DSSException
	 *             if an error occurred
	 */
	RemoteDocument extendDocument(final RemoteDocument toExtendDocument, final RemoteSignatureParameters parameters) throws DSSException;

}
