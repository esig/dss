package eu.europa.esig.jaxb.validationreport.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.jaxb.validationreport.enums.ConstraintStatus;
import eu.europa.esig.jaxb.validationreport.enums.MainIndication;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;
import eu.europa.esig.jaxb.validationreport.enums.RevocationReason;
import eu.europa.esig.jaxb.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.jaxb.validationreport.enums.SubIndication;
import eu.europa.esig.jaxb.validationreport.enums.TypeOfProof;

public class UriBasedEnumParserTest {

	@Test
	public void mainStatusIndication() {
		for (MainIndication msi : MainIndication.values()) {
			String string = UriBasedEnumParser.print(msi);
			assertNotNull(string);
			assertEquals(msi, UriBasedEnumParser.parseMainIndication(string));
		}
	}

	@Test
	public void objectType() {
		for (ObjectType ot : ObjectType.values()) {
			String string = UriBasedEnumParser.print(ot);
			assertNotNull(string);
			assertEquals(ot, UriBasedEnumParser.parseObjectType(string));
		}
	}

	@Test
	public void revocationReason() {
		for (RevocationReason rr : RevocationReason.values()) {
			String string = UriBasedEnumParser.print(rr);
			assertNotNull(string);
			assertEquals(rr, UriBasedEnumParser.parseRevocationReason(string));
		}
	}

	@Test
	public void signatureValidationProcessID() {
		for (SignatureValidationProcessID svpid : SignatureValidationProcessID.values()) {
			String string = UriBasedEnumParser.print(svpid);
			assertNotNull(string);
			assertEquals(svpid, UriBasedEnumParser.parseSignatureValidationProcessID(string));
		}
	}

	@Test
	public void statusSubIndication() {
		for (SubIndication ssi : SubIndication.values()) {
			String string = UriBasedEnumParser.print(ssi);
			assertNotNull(string);
			assertEquals(ssi, UriBasedEnumParser.parseSubIndication(string));
		}
	}

	@Test
	public void typeOfProof() {
		for (TypeOfProof top : TypeOfProof.values()) {
			String string = UriBasedEnumParser.print(top);
			assertNotNull(string);
			assertEquals(top, UriBasedEnumParser.parseTypeOfProof(string));
		}
	}

	@Test
	public void constraintStatus() {
		for (ConstraintStatus cs : ConstraintStatus.values()) {
			String string = UriBasedEnumParser.print(cs);
			assertNotNull(string);
			assertEquals(cs, UriBasedEnumParser.parseConstraintStatus(string));
		}
	}

}
