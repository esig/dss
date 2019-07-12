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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;

public class CAdESBaselineLTTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello world".getBytes());

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}

	@Override
	public void checkCertificateValue() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certValues));
	}

	@Override
	public void checkCompleteCertificateReference() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certificateRefs));
	}

	@Override
	public void checkRevocationValues() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_revocationValues));
	}

	@Override
	public void checkCompleteRevocationReferences() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_revocationRefs));
	}

	@Override
	public void checkCAdESCTimestamp() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp));
	}

	@Override
	public void checkTimestampedCertsCrlsReferences() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp));
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
