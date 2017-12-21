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
package eu.europa.esig.dss.signature;

import java.io.Serializable;
import java.util.List;

import eu.europa.esig.dss.AbstractSerializableSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

/**
 * This interface {@code RemoteMultipleDocumentsSignatureService} provides operations for the signature creation.
 * 
 * This interface allows to sign a set of documents.
 * 
 * Supported implementations :
 * -XAdES Enveloping
 * -XAdES Detached
 * -ASiC-S/E with XAdES
 * -ASiC-S/E with CAdES
 * 
 */
public interface RemoteMultipleDocumentsSignatureService<DOC, SP extends AbstractSerializableSignatureParameters> extends Serializable {

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
	ToBeSigned getDataToSign(final List<DOC> toSignDocuments, final SP parameters) throws DSSException;

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
	DSSDocument signDocument(final List<DOC> toSignDocuments, final SP parameters, SignatureValue signatureValue) throws DSSException;

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
	DSSDocument extendDocument(final DOC toExtendDocument, final SP parameters) throws DSSException;

}