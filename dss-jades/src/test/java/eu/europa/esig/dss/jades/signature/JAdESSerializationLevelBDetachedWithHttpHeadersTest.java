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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

class JAdESSerializationLevelBDetachedWithHttpHeadersTest extends AbstractJAdESMultipleDocumentSignatureTest {

	private MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private List<DSSDocument> documentsToSign;
	private Date signingDate;

	@BeforeEach
	void init() throws Exception {
		JAdESService jadesService = new JAdESService(getCompleteCertificateVerifier());
		jadesService.setTspSource(getGoodTsa());
		service = jadesService;
		
		signingDate = new Date();
		
		documentsToSign = new ArrayList<>();
		documentsToSign.add(new HTTPHeader("content-type", "application/json"));
		documentsToSign.add(new HTTPHeader("x-example", "HTTP Headers Example"));
		documentsToSign.add(new HTTPHeader("x-example", "Duplicated Header"));
		
		DSSDocument messageBodyDocument = new FileDocument("src/test/resources/sample.json");
		byte[] digest = messageBodyDocument.getDigestValue(DigestAlgorithm.SHA1);
		documentsToSign.add(new HTTPHeader("Digest", "SHA=" + Utils.toBase64(digest)));
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
		signatureParameters.setSigDMechanism(SigDMechanism.HTTP_HEADERS);
		signatureParameters.setBase64UrlEncodedPayload(false);

		return signatureParameters;
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		// change order
		List<DSSDocument> detachedContents = new ArrayList<>();

		detachedContents.add(new HTTPHeader("x-example", "HTTP Headers Example"));
		DSSDocument messageBodyDocument = new FileDocument("src/test/resources/sample.json");
		byte[] digest = messageBodyDocument.getDigestValue(DigestAlgorithm.SHA1);
		detachedContents.add(new HTTPHeader("Digest", "SHA=" + Utils.toBase64(digest)));
		detachedContents.add(new HTTPHeader("content-type", "application/json"));
		detachedContents.add(new HTTPHeader("x-example", "Duplicated Header"));
		
		return detachedContents;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.JOSE_JSON;
	}

}
