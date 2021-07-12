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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.w3c.dom.Element;

import java.math.BigInteger;

/**
 * Utils for a XAdES CertificateRef extraction
 */
public final class XAdESCertificateRefExtractionUtils {

	private XAdESCertificateRefExtractionUtils() {
	}

	/**
	 * Extracts a {@code CertificateRef} from a V1 {@code certRefElement}
	 *
	 * @param certRefElement {@link Element} V1 certRef element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link CertificateRef}
	 */
	public static CertificateRef createCertificateRefFromV1(Element certRefElement, XAdESPaths xadesPaths) {
		if (certRefElement != null) {
			Digest certDigest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(certRefElement, xadesPaths.getCurrentCertDigest()));
			if (certDigest != null) {
				CertificateRef certRef = new CertificateRef();
				certRef.setCertDigest(certDigest);
				certRef.setCertificateIdentifier(getCertificateIdentifierV1(certRefElement, xadesPaths));
				return certRef;
			}
		}
		return null;
	}

	/**
	 * Extracts a {@code CertificateRef} from a V2 {@code certRefElement}
	 *
	 * @param certRefElement {@link Element} V2 certRef element
	 * @param xadesPaths {@link XAdESPaths}
	 * @return {@link CertificateRef}
	 */
	public static CertificateRef createCertificateRefFromV2(Element certRefElement, XAdESPaths xadesPaths) {
		if (certRefElement != null) {
			Digest certDigest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(certRefElement, xadesPaths.getCurrentCertDigest()));
			if (certDigest != null) {
				CertificateRef certRef = new CertificateRef();
				certRef.setCertDigest(certDigest);
				certRef.setCertificateIdentifier(getCertificateIdentifierV2(certRefElement, xadesPaths));
				return certRef;
			}
		}
		return null;
	}

	private static SignerIdentifier getCertificateIdentifierV1(Element certRefElement, XAdESPaths xadesPaths) {
		SignerIdentifier signerIdentifier = new SignerIdentifier();

		final Element issuerNameEl = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialIssuerNamePath());
		if (issuerNameEl != null) {
			signerIdentifier.setIssuerName(DSSUtils.getX500PrincipalOrNull(issuerNameEl.getTextContent()));
		}

		final Element serialNumberEl = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialSerialNumberPath());
		if (serialNumberEl != null) {
			final String serialNumberText = serialNumberEl.getTextContent();
			signerIdentifier.setSerialNumber(new BigInteger(Utils.trim(serialNumberText)));
		}

		return signerIdentifier;
	}

	private static SignerIdentifier getCertificateIdentifierV2(Element certRefElement, XAdESPaths xadesPaths) {
		final Element issuerSerialV2Element = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialV2Path());
		if (issuerSerialV2Element == null) {
			// Tag issuerSerialV2 is optional
			return null;
		}

		final String textContent = issuerSerialV2Element.getTextContent();
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(Utils.fromBase64(textContent));
		return DSSASN1Utils.toSignerIdentifier(issuerSerial);
	}

}
