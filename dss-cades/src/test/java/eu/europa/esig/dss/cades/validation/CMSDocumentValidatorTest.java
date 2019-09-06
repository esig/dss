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
package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.validation.AbstractTestValidator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class CMSDocumentValidatorTest extends AbstractTestValidator {

	private static final String PATH = "src/test/resources/validation/dss-768/FD1&FD2&FEA.pdf.p7m";

	@Test
	public void testCMSOnly() throws IOException, CMSException {
		CMSSignedData cmsSignedData = new CMSSignedData(new FileInputStream(PATH));
		CMSDocumentValidator validator = new CMSDocumentValidator(cmsSignedData);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	public void testFileDocument() {
		CMSDocumentValidator validator = new CMSDocumentValidator(new FileDocument(PATH));
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	public void testInMemoryDocument() throws FileNotFoundException {
		CMSDocumentValidator validator = new CMSDocumentValidator(new InMemoryDocument(new FileInputStream(PATH)));
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new CMSDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new CMSDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new FileDocument(PATH));
		documents.add(new FileDocument("src/test/resources/validation/CAdESDoubleLTA.p7m"));
		documents.add(new FileDocument("src/test/resources/validation/counterSig.p7m"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-cades.p7m");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/validation/dss-916/test.txt");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		// not applicable
		return null;
	}

}
