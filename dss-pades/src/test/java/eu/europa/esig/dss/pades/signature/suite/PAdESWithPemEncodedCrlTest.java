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
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.asn1.BERTags;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

@Tag("slow")
public class PAdESWithPemEncodedCrlTest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private static Stream<Arguments> data() {
		Object[] objects = { SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T, 
				SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA };

		Collection<Arguments> dataToRun = new ArrayList<>();
		for (Object obj : objects) {
			dataToRun.add(Arguments.of(obj));
		}
		return dataToRun.stream();
	}

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument(PAdESTwoSignersLTALevelTest.class.getResourceAsStream("/sample.pdf"));
		
		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@ParameterizedTest(name = "SignatureLevel {index} : {0}")
	@MethodSource("data")
	public void test(SignatureLevel level) {
		signatureParameters.setSignatureLevel(level);
		super.signAndVerify();
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);
		OfflineRevocationSource<CRL> crlSource = advancedSignature.getCRLSource();
		Set<EncapsulatedRevocationTokenIdentifier<CRL>> allRevocationBinaries = crlSource.getAllRevocationBinaries();
		for (EncapsulatedRevocationTokenIdentifier<CRL> identifier : allRevocationBinaries) {
			assertTrue(isDerEncoded(identifier.getBinaries()));
		}
	}
	
	private boolean isDerEncoded(byte[] binaries) {
		return binaries != null && binaries.length > 0 && (BERTags.SEQUENCE | BERTags.CONSTRUCTED) == binaries[0];
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER_WITH_PEM_CRL;
	}
	
}
