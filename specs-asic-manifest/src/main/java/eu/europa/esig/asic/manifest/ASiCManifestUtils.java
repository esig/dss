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
package eu.europa.esig.asic.manifest;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * Contains utils for dealing with ASiC Manifest
 */
public final class ASiCManifestUtils extends XSDAbstractUtils {

	/** The ASiC Manifest XSD schema path */
	public static final String ASIC_MANIFEST = "/xsd/en_31916201v010101.xsd";

	/** Singleton */
	private static ASiCManifestUtils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	/**
	 * Empty constructor
	 */
	private ASiCManifestUtils() {
		// empty
	}

	/**
	 * Returns the instance of {@code ASiCManifestUtils}
	 *
	 * @return {@link ASiCManifestUtils}
	 */
	public static ASiCManifestUtils getInstance() {
		if (singleton == null) {
			singleton = new ASiCManifestUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.asic.manifest.jaxb.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.add(new StreamSource(ASiCManifestUtils.class.getResourceAsStream(ASIC_MANIFEST)));
		return xsdSources;
	}

}
