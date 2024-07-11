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
package eu.europa.esig.dss.test.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractPkiFactoryTestMultipleDocumentsSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters>
		extends AbstractPkiFactoryTestSignature<SP, TP> {

	protected abstract List<DSSDocument> getDocumentsToSign();

	protected abstract MultipleDocumentsSignatureService<SP, TP> getService();

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return getDocumentsToSign();
	}

	@Override
	protected DSSDocument sign() {
		List<DSSDocument> toBeSigned = getDocumentsToSign();
		SP params = getSignatureParameters();
		MultipleDocumentsSignatureService<SP, TP> service = getService();

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getSignatureAlgorithm(), getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
		return service.signDocument(toBeSigned, params, signatureValue);
	}

}
