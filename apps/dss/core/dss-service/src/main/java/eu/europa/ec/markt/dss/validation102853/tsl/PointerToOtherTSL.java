/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;

import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.tsl.jaxb.tsl.AnyType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceDigitalIdentityListType;

/**
 * Wrapper for the tag OtherTSLPointer
 *
 * @version $Revision: 1154 $ - $Date: 2012-02-23 16:04:49 +0100 (Thu, 23 Feb 2012) $
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
	List<X509Certificate> getDigitalIdentity() {

		if (getServiceDigitalIdentities() == null) {

			return null;
		}
		final List<X509Certificate> x509DigitalIdentityList = new ArrayList<X509Certificate>();
		for (final DigitalIdentityListType digitalIdentityList : getServiceDigitalIdentities()) {

			final List<DigitalIdentityType> digitalIdList = digitalIdentityList.getDigitalId();
			for (final DigitalIdentityType currentDigitalIdentity : digitalIdList) {

				if (currentDigitalIdentity.getX509Certificate() != null) {

					final X509Certificate cert = DSSUtils.loadCertificate(currentDigitalIdentity.getX509Certificate());
					if (LOG.isDebugEnabled()) {

						LOG.debug("Territory {} signed by {}", new Object[]{getTerritory(), cert.getSubjectDN()});
					}
					x509DigitalIdentityList.add(cert);
					break;
				}
			}
		}
		return x509DigitalIdentityList.size() > 0 ? x509DigitalIdentityList : null;
	}
}
