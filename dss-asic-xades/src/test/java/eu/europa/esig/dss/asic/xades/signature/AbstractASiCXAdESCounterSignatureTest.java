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
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.test.signature.AbstractCounterSignatureTest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCXAdESCounterSignatureTest extends AbstractCounterSignatureTest<ASiCWithXAdESSignatureParameters, 
					XAdESTimestampParameters, XAdESCounterSignatureParameters> {

	@Override
	protected MimeType getExpectedMime() {
		if (ASiCContainerType.ASiC_S.equals(getSignatureParameters().aSiC().getContainerType())) {
			return MimeTypeEnum.ASICS;
		}
		return MimeTypeEnum.ASICE;
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.XAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertEquals(getSignatureParameters().aSiC().getContainerType(), diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
	}

}
