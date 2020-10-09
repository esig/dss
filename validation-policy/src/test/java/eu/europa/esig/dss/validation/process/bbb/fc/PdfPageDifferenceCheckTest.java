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
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfPageDifferenceCheck;

public class PdfPageDifferenceCheckTest extends AbstractTestCheck {

	@Test
	public void valid() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfPageDifferenceCheck ppdc = new PdfPageDifferenceCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		ppdc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void fail() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();
		xmlModificationDetection.getPageDifference().add(getXmlModification(2));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfPageDifferenceCheck ppdc = new PdfPageDifferenceCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		ppdc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void annotationOverlap() throws Exception {
		XmlSignature sig = new XmlSignature();
		
		XmlPDFRevision xmlPDFRevision = new XmlPDFRevision();
		XmlModificationDetection xmlModificationDetection = new XmlModificationDetection();
		xmlModificationDetection.getAnnotationOverlap().add(getXmlModification(1));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfPageDifferenceCheck ppdc = new PdfPageDifferenceCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		ppdc.execute();

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
		xmlModificationDetection.getPageDifference().add(getXmlModification(3));
		xmlPDFRevision.setModificationDetection(xmlModificationDetection);

		sig.setPDFRevision(xmlPDFRevision);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlFC result = new XmlFC();
		PdfPageDifferenceCheck ppdc = new PdfPageDifferenceCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		ppdc.execute();

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
