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
package eu.europa.esig.dss.cades.requirements;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.OID;

public class CAdESBaselineBTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello world".getBytes());

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}

	@Override
	public void checkSignatureTimeStampPresent() {
		// Not present in baseline B
	}

	@Override
	public void checkCertificateValue() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCompleteCertificateReference() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkRevocationValues() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCompleteRevocationReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCAdESCTimestamp() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
		assertTrue(counter >= 0);
	}

	@Override
	public void checkTimestampedCertsCrlsReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp);
		assertTrue(counter >= 0);
	}

	@Override
	public void checkArchiveTimeStampV3() {
		int counter = countUnsignedAttribute(OID.id_aa_ets_archiveTimestampV3);
		assertEquals(0, counter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
