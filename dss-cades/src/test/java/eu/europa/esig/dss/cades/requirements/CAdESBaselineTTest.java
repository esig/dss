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
package eu.europa.esig.dss.cades.requirements;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.OID;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESBaselineTTest extends AbstractCAdESRequirementChecks {

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		CAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		return signatureParameters;
	}

	@Override
	protected void checkCertificateValue(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	protected void checkCompleteCertificateReference(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	protected void checkRevocationValues(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_revocationValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	protected void checkCompleteRevocationReferences(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	protected void checkCAdESCTimestamp(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
		assertTrue(counter >= 0);
	}

	@Override
	protected void checkTimestampedCertsCrlsReferences(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp);
		assertTrue(counter >= 0);
	}

	@Override
	protected void checkArchiveTimeStampV3(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, OID.id_aa_ets_archiveTimestampV3);
		assertEquals(0, counter);
	}

}
