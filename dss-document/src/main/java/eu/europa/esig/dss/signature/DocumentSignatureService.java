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
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.io.Serializable;

/**
 * This interface {@code DocumentSignatureService} provides operations for the signature creation and for its extension.
 *
 *
 */
public interface DocumentSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters> extends Serializable {

	/**
	 * Retrieves the bytes of the data that need to be signed based on the {@code toSignDocument} and {@code parameters}.
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
	 */
	ToBeSigned getDataToSign(final DSSDocument toSignDocument, final SP parameters);

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
	 * Signs the toSignDocument with the provided signatureValue.
	 *
	 * @param toSignDocument
	 *            document to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param signatureValue
	 *            the signature value to incorporate
	 * @return the signed document ({@code toSignDocument} with the incorporated signature or the detached signature)
	 */
	DSSDocument signDocument(final DSSDocument toSignDocument, final SP parameters, SignatureValue signatureValue);

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
	 * This setter allows to define the TSP (timestamp provider) source.
	 *
	 * @param tspSource
	 *            The time stamp source which is used when timestamping the signature.
	 */
	void setTspSource(final TSPSource tspSource);

	/**
	 * This method allows to compute a content-timestamp (which is added in the
	 * signed properties)
	 * 
	 * @param toSignDocument
	 *                       document to sign or the already existing signature
	 * @param parameters
	 *                       set of the driving signing parameters
	 * @return a timestamp token
	 */
	TimestampToken getContentTimestamp(final DSSDocument toSignDocument, final SP parameters);

	/**
	 * This method allows to add a timestamp to an unsigned document
	 * 
	 * @param toTimestampDocument
	 *                            the document to be timestamped
	 * @param parameters
	 *                            set of the driving timestamping parameters
	 * @return the timestamped document
	 */
	DSSDocument timestamp(final DSSDocument toTimestampDocument, final TP parameters);

}
