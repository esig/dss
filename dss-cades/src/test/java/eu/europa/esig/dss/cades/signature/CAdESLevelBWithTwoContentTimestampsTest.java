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
package eu.europa.esig.dss.cades.signature;

import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Before;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public class CAdESLevelBWithTwoContentTimestampsTest extends AbstractCAdESTestSignature {

	private DocumentSignatureService<CAdESSignatureParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World".getBytes());

		TSPSource tspSource = getGoodTsa();

		TimeStampToken timeStampResponse1 = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, documentToSign));
		TimestampToken contentTimestamp1 = new TimestampToken(timeStampResponse1, TimestampType.CONTENT_TIMESTAMP);

		TimeStampToken timeStampResponse2 = tspSource.getTimeStampResponse(DigestAlgorithm.SHA1, DSSUtils.digest(DigestAlgorithm.SHA1, documentToSign));
		TimestampToken contentTimestamp2 = new TimestampToken(timeStampResponse2, TimestampType.CONTENT_TIMESTAMP);

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getSigningCert());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp1, contentTimestamp2));

		service = new CAdESService(getCompleteCertificateVerifier());
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
