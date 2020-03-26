package eu.europa.esig.dss.xades.validation;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPaths;

public final class XAdESRevocationRefExtractionUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESRevocationRefExtractionUtils.class);

	private XAdESRevocationRefExtractionUtils() {
	}

	public static OCSPRef createOCSPRef(final XAdESPaths xadesPaths, final Element ocspRefElement) {

		Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentDigestAlgAndValue()));
		if (digest == null) {
			LOG.warn("Skipped OCSPRef (missing DigestAlgAndValue)");
			return null;
		}

		ResponderId responderId = getOCSPResponderId(xadesPaths, ocspRefElement);
		if (responderId == null) {
			LOG.warn("Skipped OCSPRef (missing OCSPIdentifier / ResponderID)");
			return null;
		}

		Date producedAtDate = getOCSPProducedAtDate(xadesPaths, ocspRefElement);
		if (producedAtDate == null) {
			LOG.warn("Skipped OCSPRef (missing OCSPIdentifier / ProducedAt)");
			return null;
		}


		return new OCSPRef(digest, producedAtDate, responderId);
	}

	private static Date getOCSPProducedAtDate(final XAdESPaths xadesPaths, final Element ocspRefElement) {
		Date producedAtDate = null;
		final Element producedAtEl = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefProducedAt());
		if (producedAtEl != null) {
			producedAtDate = DomUtils.getDate(producedAtEl.getTextContent());
		}
		return producedAtDate;
	}

	private static ResponderId getOCSPResponderId(final XAdESPaths xadesPaths, final Element ocspRefElement) {
		X500Principal responderName = null;
		byte[] ski = null;
		String currentOCSPRefResponderIDByName = xadesPaths.getCurrentOCSPRefResponderIDByName();
		String currentOCSPRefResponderIDByKey = xadesPaths.getCurrentOCSPRefResponderIDByKey();
		if (currentOCSPRefResponderIDByName != null && currentOCSPRefResponderIDByKey != null) {
			final Element responderIdByName = DomUtils.getElement(ocspRefElement, currentOCSPRefResponderIDByName);
			if (responderIdByName != null) {
				responderName = DSSUtils.getX500PrincipalOrNull(responderIdByName.getTextContent());
			}

			final Element responderIdByKey = DomUtils.getElement(ocspRefElement, currentOCSPRefResponderIDByKey);
			if (responderIdByKey != null) {
				ski = Utils.fromBase64(responderIdByKey.getTextContent());
			}
		} else {
			final Element responderIdElement = DomUtils.getElement(ocspRefElement, xadesPaths.getCurrentOCSPRefResponderID());
			if (responderIdElement != null) {
				responderName = DSSUtils.getX500PrincipalOrNull(responderIdElement.getTextContent());
			}
		}

		if (responderName != null || Utils.isArrayNotEmpty(ski)) {
			return new ResponderId(responderName, ski);
		}
		return null;
	}

	public static CRLRef createCRLRef(XAdESPaths xadesPaths, Element crlRefNode) {
		final Digest digest = DSSXMLUtils.getDigestAndValue(DomUtils.getElement(crlRefNode, xadesPaths.getCurrentDigestAlgAndValue()));
		if (digest == null) {
			LOG.warn("Skipped CRLRef (missing DigestAlgAndValue)");
			return null;
		}
		// TODO CRLIdentifier
		return new CRLRef(digest);
	}

}
