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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.ArrayList;
import java.util.List;

public class ASiCWithXAdESValidatorTest extends AbstractTestValidator {

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new ASiCContainerWithXAdESValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new ASiCContainerWithXAdESValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/onefile-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asice"));
		documents.add(new FileDocument("src/test/resources/validation/multifiles-ok.asics"));
		documents.add(new FileDocument("src/test/resources/validation/libreoffice.ods"));
		documents.add(new FileDocument("src/test/resources/validation/libreoffice.odt"));
		documents.add(new FileDocument("src/test/resources/validation/open-document-signed.odt"));
		documents.add(new FileDocument("src/test/resources/validation/open-document-resigned.odt"));
		documents.add(new FileDocument("src/test/resources/signable/asic_xades.zip"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-container.asice");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/manifest-sample.xml");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new FileDocument("src/test/resources/validation/no-signature.asics");
	}

}