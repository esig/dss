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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.io.Serializable;
import java.util.List;

/**
 * This interface {@code MultipleDocumentsSignatureService} provides operations for the signature creation and for its
 * extension.
 *
 * @param <SP> implementation of signature parameters corresponding to the supported signature format
 * @param <TP> implementation of timestamp parameters corresponding to the supported document format
 */
public interface MultipleDocumentsSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters> extends Serializable {

	/**
	 * Creates a content-timestamp attribute (to be include in the signed-data)
	 * 
	 * @param toSignDocuments
	 *                        list of documents to sign
	 * @param parameters
	 *                        set of the driving signing parameters
	 * @return a timestamp token
	 */
	TimestampToken getContentTimestamp(final List<DSSDocument> toSignDocuments, final SP parameters);

	/**
	 * Retrieves the bytes of the data that need to be signed based on the
	 * {@code toSignDocuments} and {@code parameters}. When {@code toSignDocuments}
	 * contains an already existing signature the returned bytes are related to a
	 * new parallel signature.
	 * 
	 * @param toSignDocuments
	 *                        list of documents to sign
	 * @param parameters
	 *                        set of the driving signing parameters
	 * @return the data to be signed
	 */
	ToBeSigned getDataToSign(final List<DSSDocument> toSignDocuments, final SP parameters);

	/**
	 * Verifies the signature value against a {@code ToBeSigned} and a
	 * {@code CertificateToken}
	 * 
	 * @param toBeSigned         the signed data
	 * @param signatureValue     the signature value
	 * @param signingCertificate the used certificate to create the signature value
	 * @return true if the signature value is valid
	 */
	boolean isValidSignatureValue(ToBeSigned toBeSigned, SignatureValue signatureValue, CertificateToken signingCertificate);

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
	 */
	DSSDocument signDocument(final List<DSSDocument> toSignDocuments, final SP parameters, SignatureValue signatureValue);

	/**
	 * Extends the level of the signatures in the {@code toExtendDocument}
	 *
	 * @param toExtendDocument
	 *            document to extend
	 * @param parameters
	 *            set of the driving signing parameters
	 * @return the extended signature
	 */
	DSSDocument extendDocument(final DSSDocument toExtendDocument, final SP parameters);

	/**
	 * Timestamps the toSignDocuments with the provided signatureValue.
	 *
	 * @param toTimestampDocuments
	 *                             list of documents to timestamp
	 * @param parameters
	 *                             set of the driving timestamping parameters
	 * @return the container with the added timestamp token
	 */
	DSSDocument timestamp(final List<DSSDocument> toTimestampDocuments, final TP parameters);

}
