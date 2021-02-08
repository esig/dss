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
package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfAnnotationOverlapCheck;

public class PdfAnnotationOverlapCheckTest extends AbstractTestCheck {

	@Test
	public void valid() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfAnnotationOverlapCheck paoc = new PdfAnnotationOverlapCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		paoc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void fail() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();
		xmlModificationDetection.getAnnotationOverlap().add(getXmlModification(1));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfAnnotationOverlapCheck paoc = new PdfAnnotationOverlapCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		paoc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void visualDifference() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();
		xmlModificationDetection.getVisualDifference().add(getXmlModification(1));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfAnnotationOverlapCheck paoc = new PdfAnnotationOverlapCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		paoc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void multipleFailure() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();
		xmlModificationDetection.getAnnotationOverlap().add(getXmlModification(1));
		xmlModificationDetection.getAnnotationOverlap().add(getXmlModification(2));
		xmlModificationDetection.getVisualDifference().add(getXmlModification(1));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfAnnotationOverlapCheck paoc = new PdfAnnotationOverlapCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		paoc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
	
	private XmlModification getXmlModification(int page) {
		XmlModification xmlModification = new XmlModification();
		xmlModification.setPage(BigInteger.valueOf(page));
		return xmlModification;
	}

}
