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
package eu.europa.esig.dss.cades;

import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CMSUtilsTest {
	
	@Test
	public void cmsSignedDataEqualTest() throws Exception {
		String tstBase64 = "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";
		byte[] tstBinaries = Utils.fromBase64(tstBase64);
		ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(tstBinaries);
		Attribute atstV3Attibute = new Attribute(OID.id_aa_ets_archiveTimestampV3, new DERSet(asn1Primitive));
		
		CMSSignedData cmsSignedData = DSSASN1Utils.getCMSSignedData(atstV3Attibute);
		assertFalse(Arrays.equals(atstV3Attibute.getEncoded(), cmsSignedData.getEncoded()));
		assertTrue(CMSUtils.isCMSSignedDataEqual(cmsSignedData, DSSASN1Utils.getCMSSignedData(atstV3Attibute)));
		
		String berEncodedTST = "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";
		assertFalse(CMSUtils.isCMSSignedDataEqual(cmsSignedData, new CMSSignedData(Utils.fromBase64(berEncodedTST))));
	}

	@Test
	public void readSigningDateTest() {
		Date date = DSSUtils.getUtcDate(1900, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new Time(date)));
		date = DSSUtils.getUtcDate(1950, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new Time(date)));
		date = DSSUtils.getUtcDate(2000, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new Time(date)));
		date = DSSUtils.getUtcDate(2050, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new Time(date)));
		date = DSSUtils.getUtcDate(2100, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new Time(date)));

		date = DSSUtils.getUtcDate(1900, 0, 1);
		assertNotEquals(date, CMSUtils.readSigningDate(new ASN1UTCTime(date)));
		date = DSSUtils.getUtcDate(1950, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new ASN1UTCTime(date)));
		date = DSSUtils.getUtcDate(2000, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new ASN1UTCTime(date)));
		date = DSSUtils.getUtcDate(2050, 0, 1);
		assertNotEquals(date, CMSUtils.readSigningDate(new ASN1UTCTime(date)));
		date = DSSUtils.getUtcDate(2100, 0, 1);
		assertNotEquals(date, CMSUtils.readSigningDate(new ASN1UTCTime(date)));

		date = DSSUtils.getUtcDate(1900, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new ASN1GeneralizedTime(date)));
		date = DSSUtils.getUtcDate(1950, 0, 1);
		assertNotEquals(date, CMSUtils.readSigningDate(new ASN1GeneralizedTime(date)));
		date = DSSUtils.getUtcDate(2000, 0, 1);
		assertNotEquals(date, CMSUtils.readSigningDate(new ASN1GeneralizedTime(date)));
		date = DSSUtils.getUtcDate(2050, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new ASN1GeneralizedTime(date)));
		date = DSSUtils.getUtcDate(2100, 0, 1);
		assertEquals(date, CMSUtils.readSigningDate(new ASN1GeneralizedTime(date)));
	}

}
