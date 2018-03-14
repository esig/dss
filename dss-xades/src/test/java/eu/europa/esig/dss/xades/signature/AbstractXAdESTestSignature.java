package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.util.Collections;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public abstract class AbstractXAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractXAdESTestSignature.class);

	private static final Schema XADES_SCHEMA;

	static {
		try (FileInputStream xsd1 = new FileInputStream("src/test/resources/xsd/XAdES01903v132-201601.xsd");
				FileInputStream xsd2 = new FileInputStream("src/test/resources/xsd/XAdES01903v141-201601.xsd")) {

			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			XADES_SCHEMA = sf.newSchema(new Source[] { new StreamSource(xsd1), new StreamSource(xsd2) });
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		// In case of enveloped signature, we don't know the whole XML structure
		if (!SignaturePackaging.ENVELOPED.equals(getSignatureParameters().getSignaturePackaging())) {
			try (ByteArrayInputStream xmlIS = new ByteArrayInputStream(byteArray)) {
				Validator validator = XADES_SCHEMA.newValidator();
				validator.validate(new StreamSource(xmlIS));
			} catch (Exception e) {
				LOG.error("Invalid XML", e);
				fail(e.getMessage());
			}
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel)
				|| SignatureLevel.XAdES_C.equals(signatureLevel) || SignatureLevel.XAdES_X.equals(signatureLevel)
				|| SignatureLevel.XAdES_XL.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

}
