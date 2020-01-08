package eu.europa.esig.dss.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.SingleTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class TimestampValidatorTest
{

  @Test
  public void testWithAttached() throws Exception
  {
    final DSSDocument timestamp = new FileDocument( "src/test/resources/d-trust.tsr" );
    final DSSDocument timestampedContent = new InMemoryDocument( "Test123".getBytes() );
    final SingleTimestampValidator timestampValidator = new SingleTimestampValidator( timestamp, timestampedContent, TimestampType.CONTENT_TIMESTAMP,
	new CertificatePool() );
    timestampValidator.setCertificateVerifier( new CommonCertificateVerifier() );

    validate( timestampValidator.validateDocument() );
  }

  @Test
  public void testWithDigestDocument() throws Exception
  {

    final TimestampToken tst = new TimestampToken( DSSUtils.toByteArray( new FileDocument( "src/test/resources/d-trust.tsr" ) ),
	TimestampType.CONTENT_TIMESTAMP );
    final DigestAlgorithm algorithm = tst.getMessageImprint().getAlgorithm();
    assertNotNull( algorithm );

    final DigestDocument digestDocument = new DigestDocument( algorithm, Utils.toBase64( DSSUtils.digest( algorithm, "Test123".getBytes() ) ) );
    final SingleTimestampValidator timestampValidator = new SingleTimestampValidator( tst, digestDocument, new CertificatePool() );
    timestampValidator.setCertificateVerifier( new CommonCertificateVerifier() );

    validate( timestampValidator.validateDocument() );
  }

  @Test
  public void dss1929() throws Exception
  {
    final byte[] byteTSR = Base64.getDecoder().decode( DSSUtils.toByteArray( new FileDocument( "src/test/resources/dss-1929/ts-token.b64" ) ) );
    final byte[] byteDoc = Base64.getDecoder().decode( DSSUtils.toByteArray( new FileDocument( "src/test/resources/dss-1929/hash-value.b64" ) ) );

    final TimestampToken token = new TimestampToken( byteTSR, TimestampType.CONTENT_TIMESTAMP );
    final byte[] alt = token.getTimeStamp().getTimeStampInfo().getMessageImprintDigest();
    assertTrue( Base64.getEncoder().encodeToString( alt ).equals( Base64.getEncoder().encodeToString( byteDoc ) ) );

    final DSSDocument doc = new InMemoryDocument( byteDoc )
    {
      private static final long serialVersionUID = 1L;

      @Override
      public String getDigest( final DigestAlgorithm digestAlgorithm )
      {
	return Utils.toBase64( getBytes() );
      }
    };

    final SingleTimestampValidator timestampValidator = new SingleTimestampValidator( token, doc, new CertificatePool() );
    timestampValidator.setCertificateVerifier( new CommonCertificateVerifier() );
    final ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade()
	.unmarshall( new File( "src/test/resources/dss-1929/ts-policy.xml" ) );
    assertNotNull( constraintsParameters );

    validate( timestampValidator.validateDocument( constraintsParameters ) );
    assertThrows( IllegalArgumentException.class, () -> timestampValidator.setValidationLevel( ValidationLevel.BASIC_SIGNATURES ) );
  }

  private void validate( final Reports reports ) throws Exception
  {
    assertNotNull( reports );
    assertNotNull( reports.getDiagnosticDataJaxb() );
    assertNotNull( reports.getXmlDiagnosticData() );
    assertNotNull( reports.getDetailedReportJaxb() );
    assertNotNull( reports.getXmlDetailedReport() );
    assertNotNull( reports.getSimpleReportJaxb() );
    assertNotNull( reports.getXmlSimpleReport() );

    final SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
    final String marshalled = simpleReportFacade.marshall( reports.getSimpleReportJaxb(), true );
    assertNotNull( marshalled );

    final DiagnosticData diagnosticData = reports.getDiagnosticData();
    final List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
    assertEquals( 1, timestampList.size() );
    final TimestampWrapper timestampWrapper = timestampList.get( 0 );

    assertTrue( timestampWrapper.isMessageImprintDataFound() );
    assertTrue( timestampWrapper.isMessageImprintDataIntact() );

    final SimpleReport simpleReport = reports.getSimpleReport();
    final List<String> timestampIdList = simpleReport.getTimestampIdList();
    assertEquals( 1, timestampIdList.size() );
    assertNotNull( simpleReport.getFirstTimestampId() );
    assertNotNull( simpleReport.getIndication( simpleReport.getFirstTimestampId() ) );
    assertNotNull( simpleReport.getTimestampQualification( simpleReport.getFirstTimestampId() ) );
  }
}
