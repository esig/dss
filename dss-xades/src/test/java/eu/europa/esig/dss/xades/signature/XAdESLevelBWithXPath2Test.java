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

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.Before;

import org.apache.xml.security.transforms.Transforms;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.DSSTransform;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.DigestAlgorithm;

public class XAdESLevelBWithXPath2Test extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private DSSDocument documentToSign;

	private Date signingDate;

	@Before
	public void init() throws Exception {
		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signingDate = new Date();
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		// Stateless mode
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		
		List<DSSTransform> dssTransformList = new ArrayList<DSSTransform>();
		
		// For parallel signatures
		DSSTransform dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_XPATH2FILTER);
		dssTransform.setElementName("dsig-xpath:XPath");
		dssTransform.setNamespace(Transforms.TRANSFORM_XPATH2FILTER);
		dssTransform.setTextContent("/descendant::ds:Signature");
		dssTransform.setFilter("subtract");
		dssTransformList.add(dssTransform);
		
		// For Enveloped Signature Transform
		dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		dssTransformList.add(dssTransform);
		
		// Canonicalization is the last operation, its better to operate the canonicalization on the smaller document
		dssTransform = new DSSTransform();
		dssTransform.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
		dssTransformList.add(dssTransform);
		
		List<DSSReference> dssReferences = new ArrayList<DSSReference>();
		DSSReference ref = new DSSReference();
		ref.setUri("");
		ref.setContents(documentToSign);
		ref.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		ref.setTransforms(dssTransformList);
		
		dssReferences.add(ref);
		signatureParameters.setReferences(dssReferences);
		
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
