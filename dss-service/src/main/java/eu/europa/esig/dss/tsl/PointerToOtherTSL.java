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
package eu.europa.esig.dss.tsl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;

import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.tsl.AnyType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.jaxb.tsl.ServiceDigitalIdentityListType;

/**
 * Wrapper for the tag OtherTSLPointer
 *
 *
 */

class PointerToOtherTSL {

	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(PointerToOtherTSL.class);

	private OtherTSLPointerType pointer;

	/**
	 * The default constructor for PointerToOtherTSL.
	 *
	 * @param pointer
	 */
	PointerToOtherTSL(OtherTSLPointerType pointer) {

		this.pointer = pointer;
	}

	private List<DigitalIdentityListType> getServiceDigitalIdentities() {

		final ServiceDigitalIdentityListType serviceDigitalIdentityList = pointer.getServiceDigitalIdentities();
		if (serviceDigitalIdentityList != null) {

			return serviceDigitalIdentityList.getServiceDigitalIdentity();
		}
		return null;
	}

	/**
	 * @return
	 */
	String getTslLocation() {

		return pointer.getTSLLocation();
	}

	private Map<String, String> getProperties() {

		final Map<String, String> properties = new HashMap<String, String>();
		for (final Object textualOrOtherInfo : pointer.getAdditionalInformation().getTextualInformationOrOtherInformation()) {

			if (textualOrOtherInfo instanceof AnyType) {

				final AnyType anyInfo = (AnyType) textualOrOtherInfo;
				for (final Object content : anyInfo.getContent()) {

					if (content instanceof String) {

						if (((String) content).trim().length() > 0) {

							throw new DSSException("Unexpected String : " + content);
						}
					} else if (content instanceof JAXBElement) {

						@SuppressWarnings("rawtypes") JAXBElement jaxbElement = (JAXBElement) content;
						properties.put(jaxbElement.getName().toString(), jaxbElement.getValue().toString());
					} else if (content instanceof Element) {

						Element element = (Element) content;
						properties.put("{" + element.getNamespaceURI() + "}" + element.getLocalName(), element.getTextContent());
					} else {

						throw new DSSException("Unknown element : " + content.getClass());
					}
				}
			} else {

				throw new DSSException("Unknown type : " + textualOrOtherInfo.getClass());
			}
		}
		return properties;
	}

	/**
	 * @return
	 */
	String getMimeType() {
		return getProperties().get("{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType");
	}

	/**
	 * @return
	 */
	String getTerritory() {
		return getProperties().get("{http://uri.etsi.org/02231/v2#}SchemeTerritory");
	}

	/**
	 * FIXME: the multiple digital identities need to be taken into account.
	 *
	 * @return
	 */
	List<CertificateToken> getDigitalIdentity() {

		if (getServiceDigitalIdentities() == null) {

			return null;
		}
		final List<CertificateToken> x509DigitalIdentityList = new ArrayList<CertificateToken>();
		for (final DigitalIdentityListType digitalIdentityList : getServiceDigitalIdentities()) {

			final List<DigitalIdentityType> digitalIdList = digitalIdentityList.getDigitalId();
			for (final DigitalIdentityType currentDigitalIdentity : digitalIdList) {

				if (currentDigitalIdentity.getX509Certificate() != null) {

					final CertificateToken cert = DSSUtils.loadCertificate(currentDigitalIdentity.getX509Certificate());
					if (LOG.isDebugEnabled()) {

						LOG.debug("Territory {} signed by {}", new Object[]{getTerritory(), cert.getSubjectX500Principal().toString()});
					}
					x509DigitalIdentityList.add(cert);
					break;
				}
			}
		}
		return x509DigitalIdentityList.size() > 0 ? x509DigitalIdentityList : null;
	}
}
