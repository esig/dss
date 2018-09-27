package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.TimestampType;

public class CAdESWithContentTimestampTest {

	@Test
	public void testContentTimeStamp() throws IOException {
		File file = new File("src/test/resources/plugtest/cades/CAdES-BES/Sample_Set_11/Signature-C-BES-4.p7m");

		FileInputStream fis = new FileInputStream(file);
		ASN1InputStream asn1sInput = new ASN1InputStream(Utils.toByteArray(fis));
		ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

		ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(asn1Seq.getObjectAt(1));
		ASN1Primitive object = taggedObj.getObject();
		SignedData signedData = SignedData.getInstance(object);

		ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
		ASN1Sequence seqSignedInfo = ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0));

		SignerInfo signedInfo = SignerInfo.getInstance(seqSignedInfo);
		ASN1Set authenticatedAttributes = signedInfo.getAuthenticatedAttributes();

		boolean found = false;
		for (int i = 0; i < authenticatedAttributes.size(); i++) {
			ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(i));
			ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
			if (PKCSObjectIdentifiers.id_aa_ets_contentTimestamp.equals(attrOid)) {
				found = true;
			}
		}
		assertTrue(found);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(file));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(timestampIdList));

		boolean foundContentTimestamp = false;
		for (String timestampId : timestampIdList) {
			String timestampType = diagnosticData.getTimestampType(timestampId);
			if (TimestampType.CONTENT_TIMESTAMP.name().equals(timestampType)) {
				foundContentTimestamp = true;
			}
		}
		assertTrue(foundContentTimestamp);

		Utils.closeQuietly(asn1sInput);
		Utils.closeQuietly(fis);
	}

}
