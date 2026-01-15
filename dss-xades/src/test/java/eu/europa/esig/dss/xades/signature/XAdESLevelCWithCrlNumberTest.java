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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xml.utils.xpath.XPathUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class XAdESLevelCWithCrlNumberTest extends XAdESLevelCTest {

	@Override
	protected CertificateVerifier getCompleteCertificateVerifier() {
		CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
		certificateVerifier.setCrlSource(pkiCRLSource());
		return certificateVerifier;
	}

	@Override
	protected PKICRLSource pkiCRLSource() {
		PKICRLSource pkiCRLSource = new PKICRLSource(getCertEntityRepository()) {

			private static final long serialVersionUID = 5256346689267847682L;

			@Override
			protected void addCRLExtensions(X509v2CRLBuilder builder) {
				try {
					builder.addExtension(new ASN1ObjectIdentifier("2.5.29.20"), false, DSSASN1Utils.getDEREncoded(new ASN1Integer(1235)));
				} catch (CertIOException e) {
					fail(e);
				}
			}
		};
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MONTH, 6);
		Date nextUpdate = cal.getTime();
		pkiCRLSource.setNextUpdate(nextUpdate);
		return pkiCRLSource;
	}

	@Override
	protected void validateCompleteRevocationRefsList(NodeList completeRevocationRefsList, XAdESPath paths) {
		Node completeRevocationRefNode = completeRevocationRefsList.item(0);
		NodeList crlRefs = XPathUtils.getNodeList(completeRevocationRefNode, paths.getCurrentCRLRefsChildren());
		assertEquals(1, crlRefs.getLength());
		NodeList ocspRefs = XPathUtils.getNodeList(completeRevocationRefNode, paths.getCurrentOCSPRefsChildren());
		assertEquals(1, ocspRefs.getLength());

		Element crlIdentifier = XPathUtils.getElement(crlRefs.item(0), paths.getCurrentCRLRefCRLIdentifier());
		assertNotNull(crlIdentifier);

		Element crlIdentifierIssuer = XPathUtils.getElement(crlRefs.item(0), paths.getCurrentCRLRefCRLIdentifierIssuer());
		assertNotNull(crlIdentifierIssuer);
		Element crlIdentifierIssueTime = XPathUtils.getElement(crlRefs.item(0), paths.getCurrentCRLRefCRLIdentifierIssueTime());
		assertNotNull(crlIdentifierIssueTime);
		Element crlIdentifierNumber = XPathUtils.getElement(crlRefs.item(0), paths.getCurrentCRLRefCRLIdentifierNumber());
		assertNotNull(crlIdentifierNumber);
		assertEquals("1235", crlIdentifierNumber.getTextContent());
	}

	@Override
	protected void checkRevocationReferences(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundRevocationsProxy foundRevocations = signature.foundRevocations();
		List<OrphanRevocationWrapper> revocations = foundRevocations.getOrphanRevocationData();

		int crlRefCounter = 0;
		int ocspRefCounter = 0;
		for (OrphanRevocationWrapper revocation : revocations) {
			if (RevocationType.CRL == revocation.getRevocationType()) {
				List<RevocationRefWrapper> references = revocation.getReferences();
				assertEquals(1, references.size());
				RevocationRefWrapper crlRef = references.get(0);
				assertNotNull(crlRef.getDigestAlgoAndValue());
				assertNotNull(crlRef.getDigestAlgoAndValue().getDigestMethod());
				assertTrue(Utils.isArrayNotEmpty(crlRef.getDigestAlgoAndValue().getDigestValue()));

				assertNotNull(crlRef.getIssuer());
				assertNotNull(crlRef.getIssueTime());
				assertNotNull(crlRef.getNumber());
				assertEquals("1235", crlRef.getNumber().toString());

				assertNull(crlRef.getProductionTime());
				assertNull(crlRef.getResponderIdKey());
				assertNull(crlRef.getResponderIdName());

				++crlRefCounter;

			} else if (RevocationType.OCSP == revocation.getRevocationType()) {
				List<RevocationRefWrapper> references = revocation.getReferences();
				assertEquals(1, references.size());
				RevocationRefWrapper crlRef = references.get(0);
				assertNotNull(crlRef.getDigestAlgoAndValue());
				assertNotNull(crlRef.getDigestAlgoAndValue().getDigestMethod());
				assertTrue(Utils.isArrayNotEmpty(crlRef.getDigestAlgoAndValue().getDigestValue()));

				assertNotNull(crlRef.getProductionTime());
				assertNotNull(crlRef.getResponderIdKey());
				assertNull(crlRef.getResponderIdName());

				assertNull(crlRef.getIssuer());
				assertNull(crlRef.getIssueTime());
				assertNull(crlRef.getNumber());

				++ocspRefCounter;
			}
		}
		assertEquals(1, crlRefCounter);
		assertEquals(1, ocspRefCounter);
	}

}
