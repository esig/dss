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
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class CAdESBaselineLTATest extends AbstractCAdESRequirementChecks {

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		CAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		return signatureParameters;
	}

	@Override
	protected void checkSignedData(SignedData signedData) throws Exception {
		super.checkSignedData(signedData);
		checkSignedDataRevocationDataPresent(signedData);
	}

	@Override
	public void checkCertificateValue(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certValues));
	}

	@Override
	public void checkCompleteCertificateReference(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certificateRefs));
	}

	@Override
	public void checkRevocationValues(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_revocationValues));
	}

	@Override
	public void checkCompleteRevocationReferences(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_revocationRefs));
	}

	@Override
	public void checkCAdESCTimestamp(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp));
	}

	@Override
	public void checkTimestampedCertsCrlsReferences(SignerInfo signerInfo) {
		assertFalse(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp));
	}

	@Override
	public void checkArchiveTimeStampV3(SignerInfo signerInfo) {
		int counter = countUnsignedAttribute(signerInfo, OID.id_aa_ets_archiveTimestampV3);
		assertEquals(1, counter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
