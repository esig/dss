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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.io.Serializable;

/**
 * This interface {@code CounterSignatureService} provides operations for a counter-signature creation
 *
 * @param <CSP> implementation of certain format signature parameters
 */
public interface CounterSignatureService<CSP extends SerializableCounterSignatureParameters> extends Serializable {
	
	/**
	 * Retrieves the bytes of the data that need to be counter-signed from {@code signatureDocument}.
	 * {@code signatureDocument} shall be a valid signature of the same type
	 * 
	 * @param signatureDocument 
	 *           {@link DSSDocument} representing the original signature to be counter-signed
	 * @param parameters
	 *            set of the driving signing parameters for a counter-signature
	 * @return {@link ToBeSigned} to be counter-signed byte array (signature value retrieved from the {@code signatureDocument})
	 */
	ToBeSigned getDataToBeCounterSigned(final DSSDocument signatureDocument, final CSP parameters);

	/**
	 * Counter-signs the {@code signatureDocument} with the provided signatureValue.
	 *
	 * @param signatureDocument
	 *            {@link DSSDocument} to be counter-signed
	 * @param parameters
	 *            set of the driving signing parameters for a counter-signature
	 * @param signatureValue
	 *            {@link SignatureValue} the signature value to incorporate
	 * @return {@link DSSDocument} the signature document enveloping a newly created counter-signature
	 */
	DSSDocument counterSignSignature(final DSSDocument signatureDocument, final CSP parameters, final SignatureValue signatureValue);

	/**
	 * This setter allows to define the TSP (timestamp provider) source.
	 *
	 * @param tspSource
	 *            The time stamp source which is used when timestamping the signature.
	 */
	void setTspSource(final TSPSource tspSource);

}
