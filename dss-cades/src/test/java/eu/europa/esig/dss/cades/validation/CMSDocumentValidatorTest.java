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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.test.validation.AbstractTestDocumentValidator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CMSDocumentValidatorTest extends AbstractTestDocumentValidator {

	private static final String PATH = "/validation/dss-768/FD1&FD2&FEA.pdf.p7m";

	private static final FileDocument FILE_DOCUMENT;

	static {
		File originalDoc = new File("target/FD1&FD2&FEA.pdf.p7m");
		try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = CMSDocumentValidatorTest.class.getResourceAsStream(PATH)) {
			Utils.copy(is, fos);
		} catch (IOException e) {
			throw new DSSException("Unable to create the original document", e);
		}
		FILE_DOCUMENT = new FileDocument(originalDoc);
	}

	@Test
	void testCMSOnly() throws IOException {
		CMS cms = CMSUtils.parseToCMS(FILE_DOCUMENT);
		CMSDocumentValidator validator = new CMSDocumentValidator(cms);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	void testFileDocument() {
		CMSDocumentValidator validator = new CMSDocumentValidator(FILE_DOCUMENT);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	@Test
	void testInMemoryDocument() throws IOException {
		CMSDocumentValidator validator = new CMSDocumentValidator(new InMemoryDocument(FILE_DOCUMENT.openStream()));
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
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(FILE_DOCUMENT);
		documents.add(new InMemoryDocument(CMSDocumentValidatorTest.class.getResourceAsStream("/validation/CAdESDoubleLTA.p7m")));
		documents.add(new InMemoryDocument(CMSDocumentValidatorTest.class.getResourceAsStream("/validation/counterSig.p7m")));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new InMemoryDocument(CMSDocumentValidatorTest.class.getResourceAsStream("/validation/malformed-cades.p7m"));
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new InMemoryDocument(CMSDocumentValidatorTest.class.getResourceAsStream("/validation/dss-916/test.txt"));
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		// not applicable
		return null;
	}

	@Override
	protected DSSDocument getXmlEvidenceRecordDocument() {
		return new InMemoryDocument(CMSDocumentValidatorTest.class.getResourceAsStream("/validation/evidence-record/evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.xml"));
	}

}
