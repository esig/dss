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
package eu.europa.esig.trustedlist;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import eu.europa.esig.xades.XAdESUtils;
import eu.europa.esig.xmldsig.XSDAbstractUtils;

/**
 * Shadow version of TrustedListUtils.
 * 
 * Explanation : specs-trusted-list (v5.6), provides XSD files to validate the
 * trustlists XML (see dss-tsl-validation/xsd/*.xsd). Those XSD reference the
 * XADES xsd in version 1.3.2 : http://uri.etsi.org/01903/v1.3.2/XAdES.xsd.
 * 
 * This XSD file does not support the SigningCertificateV2 attribute. But this
 * attribute is used in the test validation trusted lists provided by CEF.
 * Therefore loading of CEF test trustued lists fails with a parsing error
 * (SigningCertificateV2 not expected).
 * 
 * Reference to http://uri.etsi.org/01903/v1.3.2/XAdES.xsd seems correct
 * regarding ETSI TS 119 612 V1.1.1 (2013-06) which references explicitly this
 * XSD URL. In later version of same ETSI TS 119 612 (2.1.1), the explicit
 * reference to XSD URL was removed, but the document references ETSI TS 101 903
 * (latest version), which does not talk about SigningCertificateV2 either.
 * 
 * In order to be able to use validation test cases, the easiest is to disable
 * trust list validation. This requires shadowing TrustedListUtils as it can not
 * be injected / manipulated in any wey in DSS (as well as TrustedListFacade).
 */
public final class TrustedListUtils extends XSDAbstractUtils {

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	public static final String TRUSTED_LIST_SCHEMA_LOCATION = "/xsd/ts_119612v020101_xsd.xsd";
	public static final String TRUSTED_LIST_SIE_SCHEMA_LOCATION = "/xsd/ts_119612v020101_sie_xsd.xsd"; // NOPMD Not our
																										// code (shadow
																										// class)
	public static final String TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION = "/xsd/ts_119612v020101_additionaltypes_xsd.xsd"; // NOPMD
																																// Not
																																// our
																																// code
																																// (shadow
																																// class)

	/**
	 * NRO : A flag indicating if we will validate TrustedLists against schema, or
	 * not.
	 */
	private boolean validate = true;

	private static TrustedListUtils singleton;

	private JAXBContext jc; // NOPMD Not our code (shadow class)

	private TrustedListUtils() {
	}

	public static TrustedListUtils getInstance() {
		if (singleton == null) { // NOPMD Not our code (shadow class)
			singleton = new TrustedListUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class, ObjectFactory.class,
					eu.europa.esig.trustedlist.jaxb.tslx.ObjectFactory.class,
					eu.europa.esig.trustedlist.jaxb.ecc.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public Schema getSchema() throws SAXException {
		if (validate) {
			return super.getSchema();

		} else {
			return null;
		}
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XAdESUtils.getInstance().getXSDSources();
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SIE_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(
				TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION)));
		return xsdSources;
	}

	public boolean isValidate() {
		return validate;
	}

	public void setValidate(boolean validate) {
		this.validate = validate;
	}

}
