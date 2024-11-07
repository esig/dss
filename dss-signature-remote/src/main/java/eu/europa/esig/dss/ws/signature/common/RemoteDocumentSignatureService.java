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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

import java.io.Serializable;

/**
 * This interface {@code RemoteDocumentSignatureService} provides operations for the signature creation and for its
 * extension.
 *
 */
public interface RemoteDocumentSignatureService extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the {@code toSignDocument} and {@code parameters}.
	 *
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
	
	/**
	 * Adds a timestamp to the document
	 * 
	 * @param toTimestampDocument
	 *            {@link RemoteDocument} to timestamp
	 * @param parameters
	 *            set of the driving timestamp parameters
	 * @return the timestamped {@link RemoteDocument}
	 * @throws DSSException
	 *             if an error occurred
	 */
	RemoteDocument timestamp(final RemoteDocument toTimestampDocument, final RemoteTimestampParameters parameters) throws DSSException;
	
	/**
	 * Retrieves the bytes of the data that need to be counter signed from {@code signatureDocument}.
	 * {@code signatureDocument} shall be a valid signature of the same type
	 * 
	 * @param signatureDocument 
	 *           {@link RemoteDocument} representing the original signature to be counter signed
	 * @param parameters
	 *            {@link RemoteSignatureParameters} set of the driving signing parameters for a counter signature
	 * @return {@link ToBeSignedDTO} to be counter signed byte array (signature value retrieved from the {@code signatureDocument})
	 */
	ToBeSignedDTO getDataToBeCounterSigned(final RemoteDocument signatureDocument, final RemoteSignatureParameters parameters);

	/**
	 * Counter signs the {@code signatureDocument} with the provided signatureValue.
	 *
	 * @param signatureDocument
	 *            {@link RemoteDocument} to be counter signed
	 * @param parameters
	 *            {@link RemoteSignatureParameters} set of the driving signing parameters for a counter signature
	 * @param signatureValue
	 *            {@link SignatureValueDTO} the signature value to incorporate
	 * @return {@link RemoteDocument} the signature document enveloping a newly created counter signature
	 */
	RemoteDocument counterSignSignature(final RemoteDocument signatureDocument,
			final RemoteSignatureParameters parameters, final SignatureValueDTO signatureValue);

}
