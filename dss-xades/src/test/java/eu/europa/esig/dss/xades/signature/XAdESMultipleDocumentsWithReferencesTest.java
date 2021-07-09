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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.transforms.Transforms;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESMultipleDocumentsWithReferencesTest extends AbstractXAdESMultipleDocumentsSignatureService {

	private XAdESService service;
	private XAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	@BeforeEach
	public void init() throws Exception {
		service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());
		
		FileDocument firstDocument = new FileDocument("src/test/resources/sample-c14n.xml");
		FileDocument secondDocument = new FileDocument("src/test/resources/sampleWithPlaceOfSignature.xml");
		documentToSigns = Arrays.asList(firstDocument, secondDocument);

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEmbedXML(true);
		
		List<DSSReference> dssReferences = new ArrayList<>();
		DSSReference reference1 = new DSSReference();
		reference1.setContents(firstDocument);
		reference1.setId("REF-ID1");
		reference1.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference1.setUri("#document-1");
		reference1.setType(Reference.OBJECT_URI);
		DSSTransform transform1_one = new XPath2FilterTransform("//e4", "subtract");
		DSSTransform transform1_two = new CanonicalizationTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
		reference1.setTransforms(Arrays.asList(transform1_one, transform1_two));
		dssReferences.add(reference1);

		DSSReference reference2 = new DSSReference();
		reference2.setContents(secondDocument);
		reference2.setId("REF-ID2");
		reference2.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference2.setUri("#document-2");
		reference2.setType(Reference.OBJECT_URI);
		DSSTransform transform2_one = new XPath2FilterTransform("//*[@id='data1']", "intersect");
		DSSTransform transform2_two = new CanonicalizationTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		reference2.setTransforms(Arrays.asList(transform2_one, transform2_two));
		dssReferences.add(reference2);

		signatureParameters.setReferences(dssReferences);
		
		TimestampToken contentTimestamp = service.getContentTimestamp(documentToSigns, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		
		TimestampWrapper contentTst = timestampList.get(0);
		assertEquals(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, contentTst.getType());
		
		assertTrue(contentTst.isMessageImprintDataFound());
		assertTrue(contentTst.isMessageImprintDataIntact());
		
		assertEquals(2, contentTst.getTimestampedSignedData().size());
	}

	@Override
	protected MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

}
