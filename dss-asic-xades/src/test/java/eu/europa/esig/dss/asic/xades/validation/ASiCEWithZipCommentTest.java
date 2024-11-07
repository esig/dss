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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

class ASiCEWithZipCommentTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/test-zip-comment.asice");
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		
		assertEquals(1, diagnosticData.getSignatureIdList().size());
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);

		assertEquals(
				"LIB DigiDoc4j/DEV format: application/vnd.etsi.asic-e+zip signatureProfile: ASiC_E_BASELINE_LT Java: 1.8.0_111/Oracle Corporation OS: Linux/amd64/3.10.0-514.el7.x86_64 JVM: OpenJDK 64-Bit Server VM/Oracle Corporation/25.111-b15",
				diagnosticData.getZipComment());
	}

}
