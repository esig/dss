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

import java.io.Serializable;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

/**
 * This interface {@code RemoteMultipleDocumentsSignatureService} provides operations for the signature creation.
 * 
 * This interface allows to sign a set of documents.
 * 
 * Supported implementations :
 * -XAdES Enveloping
 * -XAdES Detached
 * -JAdES Detached
 * -ASiC-S/E with XAdES
 * -ASiC-S/E with CAdES
 * 
 */
public interface RemoteMultipleDocumentsSignatureService extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the {@code toSignDocuments} and
	 * {@code parameters}
	 * . When
	 * {@code toSignDocuments} contains an already existing signature the returned bytes are related to a new parallel
	 * signature.
	 * 
	 * @param toSignDocuments
	 *            list of documents to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @return the data to be signed
	 * @throws DSSException
	 *             if an error occurred
	 */
	ToBeSignedDTO getDataToSign(final List<RemoteDocument> toSignDocuments, final RemoteSignatureParameters parameters) throws DSSException;

	/**
	 * Signs the toSignDocuments with the provided signatureValue.
	 *
	 * @param toSignDocuments
	 *            list of documents to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param signatureValue
	 *            the signature value to incorporate
	 * @return the container with the signature and the documents (ASiC) or the signature file
	 * @throws DSSException
	 *             if an error occurred
	 */
	RemoteDocument signDocument(final List<RemoteDocument> toSignDocuments, final RemoteSignatureParameters parameters, SignatureValueDTO signatureValue) throws DSSException;

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
	 * Adds timestamps to the given list of documents
	 * 
	 * @param toTimestampDocuments
	 *            a list of {@link RemoteDocument} to timestamp
	 * @param parameters
	 *            set of the driving timestamp parameters
	 * @return the timestamped {@link RemoteDocument}
	 * @throws DSSException
	 *             if an error occurred
	 */
	RemoteDocument timestamp(final List<RemoteDocument> toTimestampDocuments, final RemoteTimestampParameters parameters) throws DSSException;

}
