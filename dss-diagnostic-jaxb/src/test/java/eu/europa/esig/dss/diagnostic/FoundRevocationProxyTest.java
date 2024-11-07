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
package eu.europa.esig.dss.diagnostic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;

class FoundRevocationProxyTest {
	
	@Test
	void getRelatedRevocationByRefOriginTest() {
		XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();
		XmlSignature xmlSignature = new XmlSignature();
		XmlFoundRevocations xmlFoundRevocations = new XmlFoundRevocations();
		XmlRelatedRevocation xmlRelatedRevocation = new XmlRelatedRevocation();
		xmlRelatedRevocation.setRevocation(new XmlRevocation());
		
		XmlRevocationRef xmlRevocationRefOne = new XmlRevocationRef();
		xmlRevocationRefOne.getOrigins().add(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		XmlDigestAlgoAndValue xmlDigestAlgoAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA1);
		xmlDigestAlgoAndValue.setDigestValue(Base64.getDecoder().decode("PbxFIvJ7jIvMfax49ZehCt66gXg="));
		xmlRevocationRefOne.setDigestAlgoAndValue(xmlDigestAlgoAndValue);
		xmlRelatedRevocation.getRevocationRefs().add(xmlRevocationRefOne);

		XmlRevocationRef xmlRevocationRefTwo = new XmlRevocationRef();
		xmlRevocationRefTwo.getOrigins().add(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		xmlDigestAlgoAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA256);
		xmlDigestAlgoAndValue.setDigestValue(Base64.getDecoder().decode("EGNLBWrSFV9p1en6aiwLPEatctJ+3/Wzc0N7H9IUn8c="));
		xmlRevocationRefTwo.setDigestAlgoAndValue(xmlDigestAlgoAndValue);
		xmlRelatedRevocation.getRevocationRefs().add(xmlRevocationRefOne);
		
		xmlFoundRevocations.getRelatedRevocations().add(xmlRelatedRevocation);
		xmlSignature.setFoundRevocations(xmlFoundRevocations);
		xmlDiagnosticData.setSignatures(Arrays.asList(xmlSignature));
		
		DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
		SignatureWrapper signatureWrapper = diagnosticData.getSignatures().get(0);
		FoundRevocationsProxy foundRevocations = signatureWrapper.foundRevocations();
		assertEquals(1, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
	}
	
	@Test
	void getOrphanCertificatesByRefOriginTest() {
		XmlDiagnosticData xmlDiagnosticData = new XmlDiagnosticData();
		XmlSignature xmlSignature = new XmlSignature();
		XmlFoundRevocations xmlFoundRevocations = new XmlFoundRevocations();
		XmlOrphanRevocation xmlOrphanRevocation = new XmlOrphanRevocation();
		xmlOrphanRevocation.setToken(new XmlOrphanRevocationToken());
		
		XmlRevocationRef xmlRevocationRefOne = new XmlRevocationRef();
		xmlRevocationRefOne.getOrigins().add(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		XmlDigestAlgoAndValue xmlDigestAlgoAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA1);
		xmlDigestAlgoAndValue.setDigestValue(Base64.getDecoder().decode("PbxFIvJ7jIvMfax49ZehCt66gXg="));
		xmlRevocationRefOne.setDigestAlgoAndValue(xmlDigestAlgoAndValue);
		xmlOrphanRevocation.getRevocationRefs().add(xmlRevocationRefOne);

		XmlRevocationRef xmlRevocationRefTwo = new XmlRevocationRef();
		xmlRevocationRefTwo.getOrigins().add(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
		xmlDigestAlgoAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA256);
		xmlDigestAlgoAndValue.setDigestValue(Base64.getDecoder().decode("EGNLBWrSFV9p1en6aiwLPEatctJ+3/Wzc0N7H9IUn8c="));
		xmlRevocationRefTwo.setDigestAlgoAndValue(xmlDigestAlgoAndValue);
		xmlOrphanRevocation.getRevocationRefs().add(xmlRevocationRefOne);
		
		xmlFoundRevocations.getOrphanRevocations().add(xmlOrphanRevocation);
		xmlSignature.setFoundRevocations(xmlFoundRevocations);
		xmlDiagnosticData.setSignatures(Arrays.asList(xmlSignature));
		
		DiagnosticData diagnosticData = new DiagnosticData(xmlDiagnosticData);
		SignatureWrapper signatureWrapper = diagnosticData.getSignatures().get(0);
		FoundRevocationsProxy foundRevocations = signatureWrapper.foundRevocations();
		assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
		assertEquals(1, foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getOrphanRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
	}

}
