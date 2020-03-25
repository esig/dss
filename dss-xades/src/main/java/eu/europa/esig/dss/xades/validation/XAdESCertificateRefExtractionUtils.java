package eu.europa.esig.dss.xades.validation;

import java.math.BigInteger;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPaths;

public final class XAdESCertificateRefExtractionUtils {

	private XAdESCertificateRefExtractionUtils() {
	}

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

	private static CertificateIdentifier getCertificateIdentifierV1(Element certRefElement, XAdESPaths xadesPaths) {
		CertificateIdentifier certificateIdentifier = new CertificateIdentifier();

		final Element issuerNameEl = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialIssuerNamePath());
		if (issuerNameEl != null) {
			certificateIdentifier.setIssuerName(DSSUtils.getX500PrincipalOrNull(issuerNameEl.getTextContent()));
		}

		final Element serialNumberEl = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialSerialNumberPath());
		if (serialNumberEl != null) {
			final String serialNumberText = serialNumberEl.getTextContent();
			certificateIdentifier.setSerialNumber(new BigInteger(serialNumberText.trim()));
		}

		return certificateIdentifier;
	}

	private static CertificateIdentifier getCertificateIdentifierV2(Element certRefElement, XAdESPaths xadesPaths) {
		final Element issuerSerialV2Element = DomUtils.getElement(certRefElement, xadesPaths.getCurrentIssuerSerialV2Path());
		if (issuerSerialV2Element == null) {
			// Tag issuerSerialV2 is optional
			return null;
		}

		final String textContent = issuerSerialV2Element.getTextContent();
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(Utils.fromBase64(textContent));
		return DSSASN1Utils.toCertificateIdentifier(issuerSerial);
	}

}
